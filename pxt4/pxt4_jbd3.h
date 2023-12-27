// SPDX-License-Identifier: GPL-2.0+
/*
 * pxt4_jbd3.h
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1998--1999 Red Hat corp --- All Rights Reserved
 *
 * Ext4-specific journaling extensions.
 */

#ifndef _PXT4_JBD3_H
#define _PXT4_JBD3_H

#include <linux/fs.h>
#include <linux/jbd3.h>
#include "pxt4.h"

#define PXT4_JOURNAL(inode)	(PXT4_SB((inode)->i_sb)->s_journal)

/* Define the number of blocks we need to account to a transaction to
 * modify one block of data.
 *
 * We may have to touch one inode, one bitmap buffer, up to three
 * indirection blocks, the group and superblock summaries, and the data
 * block to complete the transaction.
 *
 * For extents-enabled fs we may have to allocate and modify up to
 * 5 levels of tree, data block (for each of these we need bitmap + group
 * summaries), root which is stored in the inode, sb
 */

#define PXT4_SINGLEDATA_TRANS_BLOCKS(sb)				\
	(pxt4_has_feature_extents(sb) ? 20U : 8U)

/* Extended attribute operations touch at most two data buffers,
 * two bitmap buffers, and two group summaries, in addition to the inode
 * and the superblock, which are already accounted for. */

#define PXT4_XATTR_TRANS_BLOCKS		6U

/* Define the minimum size for a transaction which modifies data.  This
 * needs to take into account the fact that we may end up modifying two
 * quota files too (one for the group, one for the user quota).  The
 * superblock only gets updated once, of course, so don't bother
 * counting that again for the quota updates. */

#define PXT4_DATA_TRANS_BLOCKS(sb)	(PXT4_SINGLEDATA_TRANS_BLOCKS(sb) + \
					 PXT4_XATTR_TRANS_BLOCKS - 2 + \
					 PXT4_MAXQUOTAS_TRANS_BLOCKS(sb))

/*
 * Define the number of metadata blocks we need to account to modify data.
 *
 * This include super block, inode block, quota blocks and xattr blocks
 */
#define PXT4_META_TRANS_BLOCKS(sb)	(PXT4_XATTR_TRANS_BLOCKS + \
					PXT4_MAXQUOTAS_TRANS_BLOCKS(sb))

/* Define an arbitrary limit for the amount of data we will anticipate
 * writing to any given transaction.  For unbounded transactions such as
 * write(2) and truncate(2) we can write more than this, but we always
 * start off at the maximum transaction size and grow the transaction
 * optimistically as we go. */

#define PXT4_MAX_TRANS_DATA		64U

/* We break up a large truncate or write transaction once the handle's
 * buffer credits gets this low, we need either to extend the
 * transaction or to start a new one.  Reserve enough space here for
 * inode, bitmap, superblock, group and indirection updates for at least
 * one block, plus two quota updates.  Quota allocations are not
 * needed. */

#define PXT4_RESERVE_TRANS_BLOCKS	12U

/*
 * Number of credits needed if we need to insert an entry into a
 * directory.  For each new index block, we need 4 blocks (old index
 * block, new index block, bitmap block, bg summary).  For normal
 * htree directories there are 2 levels; if the largedir feature
 * enabled it's 3 levels.
 */
#define PXT4_INDEX_EXTRA_TRANS_BLOCKS	12U

#ifdef CONFIG_QUOTA
/* Amount of blocks needed for quota update - we know that the structure was
 * allocated so we need to update only data block */
#define PXT4_QUOTA_TRANS_BLOCKS(sb) ((pxt4_quota_capable(sb)) ? 1 : 0)
/* Amount of blocks needed for quota insert/delete - we do some block writes
 * but inode, sb and group updates are done only once */
#define PXT4_QUOTA_INIT_BLOCKS(sb) ((pxt4_quota_capable(sb)) ?\
		(DQUOT_INIT_ALLOC*(PXT4_SINGLEDATA_TRANS_BLOCKS(sb)-3)\
		 +3+DQUOT_INIT_REWRITE) : 0)

#define PXT4_QUOTA_DEL_BLOCKS(sb) ((pxt4_quota_capable(sb)) ?\
		(DQUOT_DEL_ALLOC*(PXT4_SINGLEDATA_TRANS_BLOCKS(sb)-3)\
		 +3+DQUOT_DEL_REWRITE) : 0)
#else
#define PXT4_QUOTA_TRANS_BLOCKS(sb) 0
#define PXT4_QUOTA_INIT_BLOCKS(sb) 0
#define PXT4_QUOTA_DEL_BLOCKS(sb) 0
#endif
#define PXT4_MAXQUOTAS_TRANS_BLOCKS(sb) (PXT4_MAXQUOTAS*PXT4_QUOTA_TRANS_BLOCKS(sb))
#define PXT4_MAXQUOTAS_INIT_BLOCKS(sb) (PXT4_MAXQUOTAS*PXT4_QUOTA_INIT_BLOCKS(sb))
#define PXT4_MAXQUOTAS_DEL_BLOCKS(sb) (PXT4_MAXQUOTAS*PXT4_QUOTA_DEL_BLOCKS(sb))

/*
 * Ext4 handle operation types -- for logging purposes
 */
#define PXT4_HT_MISC             0
#define PXT4_HT_INODE            1
#define PXT4_HT_WRITE_PAGE       2
#define PXT4_HT_MAP_BLOCKS       3
#define PXT4_HT_DIR              4
#define PXT4_HT_TRUNCATE         5
#define PXT4_HT_QUOTA            6
#define PXT4_HT_RESIZE           7
#define PXT4_HT_MIGRATE          8
#define PXT4_HT_MOVE_EXTENTS     9
#define PXT4_HT_XATTR           10
#define PXT4_HT_EXT_CONVERT     11
#define PXT4_HT_MAX             12

/**
 *   struct pxt4_journal_cb_entry - Base structure for callback information.
 *
 *   This struct is a 'seed' structure for a using with your own callback
 *   structs. If you are using callbacks you must allocate one of these
 *   or another struct of your own definition which has this struct
 *   as it's first element and pass it to pxt4_journal_callback_add().
 */
struct pxt4_journal_cb_entry {
	/* list information for other callbacks attached to the same handle */
	struct list_head jce_list;

	/*  Function to call with this callback structure */
	void (*jce_func)(struct super_block *sb,
			 struct pxt4_journal_cb_entry *jce, int error);

	/* user data goes here */
};

/**
 * pxt4_journal_callback_add: add a function to call after transaction commit
 * @handle: active journal transaction handle to register callback on
 * @func: callback function to call after the transaction has committed:
 *        @sb: superblock of current filesystem for transaction
 *        @jce: returned journal callback data
 *        @rc: journal state at commit (0 = transaction committed properly)
 * @jce: journal callback data (internal and function private data struct)
 *
 * The registered function will be called in the context of the journal thread
 * after the transaction for which the handle was created has completed.
 *
 * No locks are held when the callback function is called, so it is safe to
 * call blocking functions from within the callback, but the callback should
 * not block or run for too long, or the filesystem will be blocked waiting for
 * the next transaction to commit. No journaling functions can be used, or
 * there is a risk of deadlock.
 *
 * There is no guaranteed calling order of multiple registered callbacks on
 * the same transaction.
 */
static inline void _pxt4_journal_callback_add(handle_t *handle,
			struct pxt4_journal_cb_entry *jce)
{
	/* Add the jce to transaction's private list */
	list_add_tail(&jce->jce_list, &handle->h_transaction->t_private_list);
}

static inline void pxt4_journal_callback_add(handle_t *handle,
			void (*func)(struct super_block *sb,
				     struct pxt4_journal_cb_entry *jce,
				     int rc),
			struct pxt4_journal_cb_entry *jce)
{
	struct pxt4_sb_info *sbi =
			PXT4_SB(handle->h_transaction->t_journal->j_private);

	/* Add the jce to transaction's private list */
	jce->jce_func = func;
	spin_lock(&sbi->s_md_lock);
	_pxt4_journal_callback_add(handle, jce);
	spin_unlock(&sbi->s_md_lock);
}


/**
 * pxt4_journal_callback_del: delete a registered callback
 * @handle: active journal transaction handle on which callback was registered
 * @jce: registered journal callback entry to unregister
 * Return true if object was successfully removed
 */
static inline bool pxt4_journal_callback_try_del(handle_t *handle,
					     struct pxt4_journal_cb_entry *jce)
{
	bool deleted;
	struct pxt4_sb_info *sbi =
			PXT4_SB(handle->h_transaction->t_journal->j_private);

	spin_lock(&sbi->s_md_lock);
	deleted = !list_empty(&jce->jce_list);
	list_del_init(&jce->jce_list);
	spin_unlock(&sbi->s_md_lock);
	return deleted;
}

int
pxt4_mark_iloc_dirty(handle_t *handle,
		     struct inode *inode,
		     struct pxt4_iloc *iloc);

/*
 * On success, We end up with an outstanding reference count against
 * iloc->bh.  This _must_ be cleaned up later.
 */

int pxt4_reserve_inode_write(handle_t *handle, struct inode *inode,
			struct pxt4_iloc *iloc);

#define pxt4_mark_inode_dirty(__h, __i)					\
		__pxt4_mark_inode_dirty((__h), (__i), __func__, __LINE__)
int __pxt4_mark_inode_dirty(handle_t *handle, struct inode *inode,
				const char *func, unsigned int line);

int pxt4_expand_extra_isize(struct inode *inode,
			    unsigned int new_extra_isize,
			    struct pxt4_iloc *iloc);
/*
 * Wrapper functions with which pxt4 calls into JBD.
 */
int __pxt4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct super_block *sb,
				    struct buffer_head *bh,
				    enum pxt4_journal_trigger_type trigger_type);

int __pxt4_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, pxt4_fsblk_t blocknr);

int __pxt4_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct super_block *sb,
				struct buffer_head *bh,
				enum pxt4_journal_trigger_type trigger_type);

int __pxt4_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh);

#define pxt4_journal_get_write_access(handle, sb, bh, trigger_type) \
	__pxt4_journal_get_write_access(__func__, __LINE__, (handle), (sb), \
					(bh), (trigger_type))
#define pxt4_forget(handle, is_metadata, inode, bh, block_nr) \
	__pxt4_forget(__func__, __LINE__, (handle), (is_metadata), (inode), \
		      (bh), (block_nr))
#define pxt4_journal_get_create_access(handle, sb, bh, trigger_type) \
	__pxt4_journal_get_create_access(__func__, __LINE__, (handle), (sb), \
					 (bh), (trigger_type))
#define pxt4_handle_dirty_metadata(handle, inode, bh) \
	__pxt4_handle_dirty_metadata(__func__, __LINE__, (handle), (inode), \
				     (bh))

handle_t *__pxt4_journal_start_sb(struct inode *inode, struct super_block *sb,
				  unsigned int line, int type, int blocks,
				  int rsv_blocks, int revoke_creds);
int __pxt4_journal_stop(const char *where, unsigned int line, handle_t *handle);

#define PXT4_NOJOURNAL_MAX_REF_COUNT ((unsigned long) 4096)

/* Note:  Do not use this for NULL handles.  This is only to determine if
 * a properly allocated handle is using a journal or not. */
static inline int pxt4_handle_valid(handle_t *handle)
{
	if ((unsigned long)handle < PXT4_NOJOURNAL_MAX_REF_COUNT)
		return 0;
	return 1;
}

static inline void pxt4_handle_sync(handle_t *handle)
{
	if (pxt4_handle_valid(handle))
		handle->h_sync = 1;
}

static inline int pxt4_handle_is_aborted(handle_t *handle)
{
	if (pxt4_handle_valid(handle))
		return is_handle_aborted(handle);
	return 0;
}

static inline int pxt4_free_metadata_revoke_credits(struct super_block *sb,
						    int blocks)
{
	/* Freeing each metadata block can result in freeing one cluster */
	return blocks * PXT4_SB(sb)->s_cluster_ratio;
}

static inline int pxt4_trans_default_revoke_credits(struct super_block *sb)
{
	return pxt4_free_metadata_revoke_credits(sb, 8);
}

#define pxt4_journal_start_sb(sb, type, nblocks)			\
	__pxt4_journal_start_sb(NULL, (sb), __LINE__, (type), (nblocks), 0,\
				pxt4_trans_default_revoke_credits(sb))

#define pxt4_journal_start(inode, type, nblocks)			\
	__pxt4_journal_start((inode), __LINE__, (type), (nblocks), 0,	\
			     pxt4_trans_default_revoke_credits((inode)->i_sb))

#define pxt4_journal_start_with_reserve(inode, type, blocks, rsv_blocks)\
	__pxt4_journal_start((inode), __LINE__, (type), (blocks), (rsv_blocks),\
			     pxt4_trans_default_revoke_credits((inode)->i_sb))

#define pxt4_journal_start_with_revoke(inode, type, blocks, revoke_creds) \
	__pxt4_journal_start((inode), __LINE__, (type), (blocks), 0,	\
			     (revoke_creds))

static inline handle_t *__pxt4_journal_start(struct inode *inode,
					     unsigned int line, int type,
					     int blocks, int rsv_blocks,
					     int revoke_creds)
{
	return __pxt4_journal_start_sb(inode, inode->i_sb, line, type, blocks,
				       rsv_blocks, revoke_creds);
}

#define pxt4_journal_stop(handle) \
	__pxt4_journal_stop(__func__, __LINE__, (handle))

#define pxt4_journal_start_reserved(handle, type) \
	__pxt4_journal_start_reserved((handle), __LINE__, (type))

handle_t *__pxt4_journal_start_reserved(handle_t *handle, unsigned int line,
					int type);

static inline handle_t *pxt4_journal_current_handle(void)
{
	return journal_current_handle();
}

static inline int pxt4_journal_extend(handle_t *handle, int nblocks, int revoke)
{
	if (pxt4_handle_valid(handle))
		return jbd3_journal_extend(handle, nblocks, revoke);
	return 0;
}

static inline int pxt4_journal_restart(handle_t *handle, int nblocks,
				       int revoke)
{
	if (pxt4_handle_valid(handle))
		return jbd3__journal_restart(handle, nblocks, revoke, GFP_NOFS);
	return 0;
}

int __pxt4_journal_ensure_credits(handle_t *handle, int check_cred,
				  int extend_cred, int revoke_cred);


/*
 * Ensure @handle has at least @check_creds credits available. If not,
 * transaction will be extended or restarted to contain at least @extend_cred
 * credits. Before restarting transaction @fn is executed to allow for cleanup
 * before the transaction is restarted.
 *
 * The return value is < 0 in case of error, 0 in case the handle has enough
 * credits or transaction extension succeeded, 1 in case transaction had to be
 * restarted.
 */
#define pxt4_journal_ensure_credits_fn(handle, check_cred, extend_cred,	\
				       revoke_cred, fn) \
({									\
	__label__ __ensure_end;						\
	int err = __pxt4_journal_ensure_credits((handle), (check_cred),	\
					(extend_cred), (revoke_cred));	\
									\
	if (err <= 0)							\
		goto __ensure_end;					\
	err = (fn);							\
	if (err < 0)							\
		goto __ensure_end;					\
	err = pxt4_journal_restart((handle), (extend_cred), (revoke_cred)); \
	if (err == 0)							\
		err = 1;						\
__ensure_end:								\
	err;								\
})

/*
 * Ensure given handle has at least requested amount of credits available,
 * possibly restarting transaction if needed. We also make sure the transaction
 * has space for at least pxt4_trans_default_revoke_credits(sb) revoke records
 * as freeing one or two blocks is very common pattern and requesting this is
 * very cheap.
 */
static inline int pxt4_journal_ensure_credits(handle_t *handle, int credits,
					      int revoke_creds)
{
	return pxt4_journal_ensure_credits_fn(handle, credits, credits,
				revoke_creds, 0);
}

static inline int pxt4_journal_blocks_per_page(struct inode *inode)
{
	if (PXT4_JOURNAL(inode) != NULL)
		return jbd3_journal_blocks_per_page(inode);
	return 0;
}

static inline int pxt4_journal_force_commit(journal_t *journal)
{
	if (journal)
		return jbd3_journal_force_commit(journal);
	return 0;
}

static inline int pxt4_jbd3_inode_add_write(handle_t *handle,
		struct inode *inode, loff_t start_byte, loff_t length)
{
	if (pxt4_handle_valid(handle))
		return jbd3_journal_inode_ranged_write(handle,
				PXT4_I(inode)->jinode, start_byte, length);
	return 0;
}

static inline int pxt4_jbd3_inode_add_wait(handle_t *handle,
		struct inode *inode, loff_t start_byte, loff_t length)
{
	if (pxt4_handle_valid(handle))
		return jbd3_journal_inode_ranged_wait(handle,
				PXT4_I(inode)->jinode, start_byte, length);
	return 0;
}

static inline void pxt4_update_inode_fsync_trans(handle_t *handle,
						 struct inode *inode,
						 int datasync)
{
	struct pxt4_inode_info *ei = PXT4_I(inode);

	if (pxt4_handle_valid(handle) && !is_handle_aborted(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		if (datasync)
			ei->i_datasync_tid = handle->h_transaction->t_tid;
	}
}

/* super.c */
int pxt4_force_commit(struct super_block *sb);

/*
 * Ext4 inode journal modes
 */
#define PXT4_INODE_JOURNAL_DATA_MODE	0x01 /* journal data mode */
#define PXT4_INODE_ORDERED_DATA_MODE	0x02 /* ordered data mode */
#define PXT4_INODE_WRITEBACK_DATA_MODE	0x04 /* writeback data mode */

int pxt4_inode_journal_mode(struct inode *inode);

static inline int pxt4_should_journal_data(struct inode *inode)
{
	return pxt4_inode_journal_mode(inode) & PXT4_INODE_JOURNAL_DATA_MODE;
}

static inline int pxt4_should_order_data(struct inode *inode)
{
	return pxt4_inode_journal_mode(inode) & PXT4_INODE_ORDERED_DATA_MODE;
}

static inline int pxt4_should_writeback_data(struct inode *inode)
{
	return pxt4_inode_journal_mode(inode) & PXT4_INODE_WRITEBACK_DATA_MODE;
}

static inline int pxt4_free_data_revoke_credits(struct inode *inode, int blocks)
{
	if (test_opt(inode->i_sb, DATA_FLAGS) == PXT4_MOUNT_JOURNAL_DATA)
		return 0;
	if (!pxt4_should_journal_data(inode))
		return 0;
	/*
	 * Data blocks in one extent are contiguous, just account for partial
	 * clusters at extent boundaries
	 */
	return blocks + 2*(PXT4_SB(inode->i_sb)->s_cluster_ratio - 1);
}

/*
 * This function controls whether or not we should try to go down the
 * dioread_nolock code paths, which makes it safe to avoid taking
 * i_rwsem for direct I/O reads.  This only works for extent-based
 * files, and it doesn't work if data journaling is enabled, since the
 * dioread_nolock code uses b_private to pass information back to the
 * I/O completion handler, and this conflicts with the jbd's use of
 * b_private.
 */
static inline int pxt4_should_dioread_nolock(struct inode *inode)
{
	if (!test_opt(inode->i_sb, DIOREAD_NOLOCK))
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 0;
	if (!(pxt4_test_inode_flag(inode, PXT4_INODE_EXTENTS)))
		return 0;
	if (pxt4_should_journal_data(inode))
		return 0;
	/* temporary fix to prevent generic/422 test failures */
	if (!test_opt(inode->i_sb, DELALLOC))
		return 0;
	return 1;
}

#endif	/* _PXT4_JBD3_H */
