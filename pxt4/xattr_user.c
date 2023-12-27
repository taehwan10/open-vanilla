// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/pxt4/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/string.h>
#include <linux/fs.h>
#include "pxt4_jbd3.h"
#include "pxt4.h"
#include "xattr.h"

static bool
pxt4_xattr_user_list(struct dentry *dentry)
{
	return test_opt(dentry->d_sb, XATTR_USER);
}

static int
pxt4_xattr_user_get(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, void *buffer, size_t size)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return pxt4_xattr_get(inode, PXT4_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
pxt4_xattr_user_set(const struct xattr_handler *handler,
		    struct mnt_idmap *idmap,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
{
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return pxt4_xattr_set(inode, PXT4_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler pxt4_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= pxt4_xattr_user_list,
	.get	= pxt4_xattr_user_get,
	.set	= pxt4_xattr_user_set,
};
