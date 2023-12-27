// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/pxt4/bitmap.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/buffer_head.h>
#include "pxt4.h"

unsigned int pxt4_count_free(char *bitmap, unsigned int numchars)
{
	return numchars * BITS_PER_BYTE - memweight(bitmap, numchars);
}

int pxt4_inode_bitmap_csum_verify(struct super_block *sb,
				  struct pxt4_group_desc *gdp,
				  struct buffer_head *bh, int sz)
{
	__u32 hi;
	__u32 provided, calculated;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	if (!pxt4_has_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_inode_bitmap_csum_lo);
	calculated = pxt4_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= PXT4_BG_INODE_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_inode_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	return provided == calculated;
}

void pxt4_inode_bitmap_csum_set(struct super_block *sb,
				struct pxt4_group_desc *gdp,
				struct buffer_head *bh, int sz)
{
	__u32 csum;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	if (!pxt4_has_metadata_csum(sb))
		return;

	csum = pxt4_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_inode_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= PXT4_BG_INODE_BITMAP_CSUM_HI_END)
		gdp->bg_inode_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}

int pxt4_block_bitmap_csum_verify(struct super_block *sb,
				  struct pxt4_group_desc *gdp,
				  struct buffer_head *bh)
{
	__u32 hi;
	__u32 provided, calculated;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	int sz = PXT4_CLUSTERS_PER_GROUP(sb) / 8;

	if (!pxt4_has_metadata_csum(sb))
		return 1;

	provided = le16_to_cpu(gdp->bg_block_bitmap_csum_lo);
	calculated = pxt4_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= PXT4_BG_BLOCK_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_block_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	return provided == calculated;
}

void pxt4_block_bitmap_csum_set(struct super_block *sb,
				struct pxt4_group_desc *gdp,
				struct buffer_head *bh)
{
	int sz = PXT4_CLUSTERS_PER_GROUP(sb) / 8;
	__u32 csum;
	struct pxt4_sb_info *sbi = PXT4_SB(sb);

	if (!pxt4_has_metadata_csum(sb))
		return;

	csum = pxt4_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_block_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= PXT4_BG_BLOCK_BITMAP_CSUM_HI_END)
		gdp->bg_block_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}
