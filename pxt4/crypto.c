// SPDX-License-Identifier: GPL-2.0

#include <linux/quotaops.h>
#include <linux/uuid.h>

#include "pxt4.h"
#include "xattr.h"
#include "pxt4_jbd3.h"

static void pxt4_fname_from_fscrypt_name(struct pxt4_filename *dst,
					 const struct fscrypt_name *src)
{
	memset(dst, 0, sizeof(*dst));

	dst->usr_fname = src->usr_fname;
	dst->disk_name = src->disk_name;
	dst->hinfo.hash = src->hash;
	dst->hinfo.minor_hash = src->minor_hash;
	dst->crypto_buf = src->crypto_buf;
}

int pxt4_fname_setup_filename(struct inode *dir, const struct qstr *iname,
			      int lookup, struct pxt4_filename *fname)
{
	struct fscrypt_name name;
	int err;

	err = fscrypt_setup_filename(dir, iname, lookup, &name);
	if (err)
		return err;

	pxt4_fname_from_fscrypt_name(fname, &name);

#if IS_ENABLED(CONFIG_UNICODE)
	err = pxt4_fname_setup_ci_filename(dir, iname, fname);
	if (err)
		pxt4_fname_free_filename(fname);
#endif
	return err;
}

int pxt4_fname_prepare_lookup(struct inode *dir, struct dentry *dentry,
			      struct pxt4_filename *fname)
{
	struct fscrypt_name name;
	int err;

	err = fscrypt_prepare_lookup(dir, dentry, &name);
	if (err)
		return err;

	pxt4_fname_from_fscrypt_name(fname, &name);

#if IS_ENABLED(CONFIG_UNICODE)
	err = pxt4_fname_setup_ci_filename(dir, &dentry->d_name, fname);
	if (err)
		pxt4_fname_free_filename(fname);
#endif
	return err;
}

void pxt4_fname_free_filename(struct pxt4_filename *fname)
{
	struct fscrypt_name name;

	name.crypto_buf = fname->crypto_buf;
	fscrypt_free_filename(&name);

	fname->crypto_buf.name = NULL;
	fname->usr_fname = NULL;
	fname->disk_name.name = NULL;

#if IS_ENABLED(CONFIG_UNICODE)
	kfree(fname->cf_name.name);
	fname->cf_name.name = NULL;
#endif
}

static bool uuid_is_zero(__u8 u[16])
{
	int i;

	for (i = 0; i < 16; i++)
		if (u[i])
			return false;
	return true;
}

int pxt4_ioctl_get_encryption_pwsalt(struct file *filp, void __user *arg)
{
	struct super_block *sb = file_inode(filp)->i_sb;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	int err, err2;
	handle_t *handle;

	if (!pxt4_has_feature_encrypt(sb))
		return -EOPNOTSUPP;

	if (uuid_is_zero(sbi->s_es->s_encrypt_pw_salt)) {
		err = mnt_want_write_file(filp);
		if (err)
			return err;
		handle = pxt4_journal_start_sb(sb, PXT4_HT_MISC, 1);
		if (IS_ERR(handle)) {
			err = PTR_ERR(handle);
			goto pwsalt_err_exit;
		}
		err = pxt4_journal_get_write_access(handle, sb, sbi->s_sbh,
						    PXT4_JTR_NONE);
		if (err)
			goto pwsalt_err_journal;
		lock_buffer(sbi->s_sbh);
		generate_random_uuid(sbi->s_es->s_encrypt_pw_salt);
		pxt4_superblock_csum_set(sb);
		unlock_buffer(sbi->s_sbh);
		err = pxt4_handle_dirty_metadata(handle, NULL, sbi->s_sbh);
pwsalt_err_journal:
		err2 = pxt4_journal_stop(handle);
		if (err2 && !err)
			err = err2;
pwsalt_err_exit:
		mnt_drop_write_file(filp);
		if (err)
			return err;
	}

	if (copy_to_user(arg, sbi->s_es->s_encrypt_pw_salt, 16))
		return -EFAULT;
	return 0;
}

static int pxt4_get_context(struct inode *inode, void *ctx, size_t len)
{
	return pxt4_xattr_get(inode, PXT4_XATTR_INDEX_ENCRYPTION,
				 PXT4_XATTR_NAME_ENCRYPTION_CONTEXT, ctx, len);
}

static int pxt4_set_context(struct inode *inode, const void *ctx, size_t len,
							void *fs_data)
{
	handle_t *handle = fs_data;
	int res, res2, credits, retries = 0;

	/*
	 * Encrypting the root directory is not allowed because e2fsck expects
	 * lost+found to exist and be unencrypted, and encrypting the root
	 * directory would imply encrypting the lost+found directory as well as
	 * the filename "lost+found" itself.
	 */
	if (inode->i_ino == PXT4_ROOT_INO)
		return -EPERM;

	if (WARN_ON_ONCE(IS_DAX(inode) && i_size_read(inode)))
		return -EINVAL;

	if (pxt4_test_inode_flag(inode, PXT4_INODE_DAX))
		return -EOPNOTSUPP;

	res = pxt4_convert_inline_data(inode);
	if (res)
		return res;

	/*
	 * If a journal handle was specified, then the encryption context is
	 * being set on a new inode via inheritance and is part of a larger
	 * transaction to create the inode.  Otherwise the encryption context is
	 * being set on an existing inode in its own transaction.  Only in the
	 * latter case should the "retry on ENOSPC" logic be used.
	 */

	if (handle) {
		res = pxt4_xattr_set_handle(handle, inode,
					    PXT4_XATTR_INDEX_ENCRYPTION,
					    PXT4_XATTR_NAME_ENCRYPTION_CONTEXT,
					    ctx, len, 0);
		if (!res) {
			pxt4_set_inode_flag(inode, PXT4_INODE_ENCRYPT);
			pxt4_clear_inode_state(inode,
					PXT4_STATE_MAY_INLINE_DATA);
			/*
			 * Update inode->i_flags - S_ENCRYPTED will be enabled,
			 * S_DAX may be disabled
			 */
			pxt4_set_inode_flags(inode, false);
		}
		return res;
	}

	res = dquot_initialize(inode);
	if (res)
		return res;
retry:
	res = pxt4_xattr_set_credits(inode, len, false /* is_create */,
				     &credits);
	if (res)
		return res;

	handle = pxt4_journal_start(inode, PXT4_HT_MISC, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	res = pxt4_xattr_set_handle(handle, inode, PXT4_XATTR_INDEX_ENCRYPTION,
				    PXT4_XATTR_NAME_ENCRYPTION_CONTEXT,
				    ctx, len, 0);
	if (!res) {
		pxt4_set_inode_flag(inode, PXT4_INODE_ENCRYPT);
		/*
		 * Update inode->i_flags - S_ENCRYPTED will be enabled,
		 * S_DAX may be disabled
		 */
		pxt4_set_inode_flags(inode, false);
		res = pxt4_mark_inode_dirty(handle, inode);
		if (res)
			PXT4_ERROR_INODE(inode, "Failed to mark inode dirty");
	}
	res2 = pxt4_journal_stop(handle);

	if (res == -ENOSPC && pxt4_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	if (!res)
		res = res2;
	return res;
}

static const union fscrypt_policy *pxt4_get_dummy_policy(struct super_block *sb)
{
	return PXT4_SB(sb)->s_dummy_enc_policy.policy;
}

static bool pxt4_has_stable_inodes(struct super_block *sb)
{
	return pxt4_has_feature_stable_inodes(sb);
}

static void pxt4_get_ino_and_lblk_bits(struct super_block *sb,
				       int *ino_bits_ret, int *lblk_bits_ret)
{
	*ino_bits_ret = 8 * sizeof(PXT4_SB(sb)->s_es->s_inodes_count);
	*lblk_bits_ret = 8 * sizeof(pxt4_lblk_t);
}

const struct fscrypt_operations pxt4_cryptops = {
	.key_prefix		= "pxt4:",
	.get_context		= pxt4_get_context,
	.set_context		= pxt4_set_context,
	.get_dummy_policy	= pxt4_get_dummy_policy,
	.empty_dir		= pxt4_empty_dir,
	.has_stable_inodes	= pxt4_has_stable_inodes,
	.get_ino_and_lblk_bits	= pxt4_get_ino_and_lblk_bits,
};
