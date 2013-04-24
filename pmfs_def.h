/*
 * FILE NAME include/linux/pmfs_fs.h
 *
 * BRIEF DESCRIPTION
 *
 * Definitions for the PMFS filesystem.
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef PMFS_DEF_H_
#define PMFS_DEF_H_

#include <linux/types.h>
#include "types.h"

/*
 * The PMFS filesystem constants/structures
 */

#define PMFS_SUPER_MAGIC 0xeffc

/*
 * Mount flags
 */
#define PMFS_MOUNT_PROTECT 0x000001            /* wprotect CR0.WP */
#define PMFS_MOUNT_XATTR_USER 0x000002         /* Extended user attributes */
#define PMFS_MOUNT_POSIX_ACL 0x000004          /* POSIX Access Control Lists */
#define PMFS_MOUNT_XIP 0x000008                /* Execute in place */
#define PMFS_MOUNT_ERRORS_CONT 0x000010        /* Continue on errors */
#define PMFS_MOUNT_ERRORS_RO 0x000020          /* Remount fs ro on errors */
#define PMFS_MOUNT_ERRORS_PANIC 0x000040       /* Panic on errors */
#define PMFS_MOUNT_HUGEMMAP 0x000080           /* Huge mappings with mmap */
#define PMFS_MOUNT_HUGEIOREMAP 0x000100        /* Huge mappings with ioremap */
#define PMFS_MOUNT_PROTECT_OLD 0x000200        /* wprotect PAGE RW Bit */

/*
 * Maximal count of links to a file
 */
#define PMFS_LINK_MAX          32000

#define PMFS_DEF_BLOCK_SIZE_4K 4096

#define PMFS_INODE_SIZE 128    /* must be power of two */
#define PMFS_INODE_BITS   7

#define PMFS_NAME_LEN 255
/*
 * Structure of a directory entry in PMFS.
 */
struct pmfs_direntry {
	__le64	ino;                    /* inode no pointed to by this entry */
	__le16	de_len;                 /* length of this directory entry */
	u8	name_len;               /* length of the directory entry name */
	u8	file_type;              /* file type */
	char	name[PMFS_NAME_LEN];   /* File name */
};

#define PMFS_DIR_PAD            4
#define PMFS_DIR_ROUND          (PMFS_DIR_PAD - 1)
#define PMFS_DIR_REC_LEN(name_len)  (((name_len) + 12 + PMFS_DIR_ROUND) & \
				      ~PMFS_DIR_ROUND)

/* PMFS supported data blocks */
#define PMFS_BLOCK_TYPE_4K     0
#define PMFS_BLOCK_TYPE_2M     1
#define PMFS_BLOCK_TYPE_1G     2
#define PMFS_BLOCK_TYPE_MAX    3

#define META_BLK_SHIFT 9

/*
 * Play with this knob to change the default block type.
 * By changing the PMFS_DEFAULT_BLOCK_TYPE to 2M or 1G,
 * we should get pretty good coverage in testing.
 */
#define PMFS_DEFAULT_BLOCK_TYPE PMFS_BLOCK_TYPE_4K

/*
 * Structure of an inode in PMFS
 */
struct pmfs_inode {
	/* Keep the inode size to within 96 bytes if possible. This is because
	 * a 64 byte log-entry can store 48 bytes of data and we would like
	 * to log an inode using only 2 log-entries
	 */
	/* first 48 bytes */
	__le16	i_rsvd;             /* checksum of this inode */
	u8	    height;         /* height of data b-tree; max 3 for now */
	u8	    i_blk_type;     /* data block size this inode uses */
	__le32	i_flags;            /* Inode flags */
	__le64	i_blocks;           /* Blocks count */
	__le64	i_size;             /* Size of data in bytes */
	__le64	root;               /* blk off relative to beginning of pmfs */
	__le32	i_mtime;            /* Inode b-tree Modification time */
	__le32	i_ctime;            /* Inode modification time */
	__le32	i_dtime;            /* Deletion Time */
	__le16	i_mode;             /* File mode */
	__le16	i_links_count;      /* Links count */

	/* second 48 bytes */
	__le64	i_xattr;            /* Extended attribute block */
	__le32	i_uid;              /* Owner Uid */
	__le32	i_gid;              /* Group Id */
	__le32	i_generation;       /* File version (for NFS) */
	__le32	i_atime;            /* Access time */

	struct {
		__le32 rdev;    /* major/minor # */
	} dev;                  /* device inode */

        __le32 padding;

        __le64 i_truncatesize;
        __le64 i_next_truncate;
};

/*
 * #define PMFS_NAME_LEN (PMFS_INODE_SIZE - offsetof(struct pmfs_inode,
 *         i_d.d_name) - 1)
 */

/* #define PMFS_SB_SIZE 128 */ /* must be power of two */
#define PMFS_SB_SIZE 512       /* must be power of two */

typedef struct pmfs_journal {
	__le64     base;
	__le32     size;
	__le32     head;
	/* the next three fields must be in the same order and together.
	 * tail and gen_id must fall in the same 8-byte quadword */
	__le32     tail;
	__le16     gen_id;   /* generation id of the log */
	__le16     pad;
	__le16     redo_logging;
} pmfs_journal_t;


/*
 * Structure of the super block in PMFS
 */
struct pmfs_super_block {
	__le16		s_sum;              /* checksum of this sb */
	__le16		s_magic;            /* magic signature */
	__le32		s_blocksize;        /* blocksize in bytes */
	__le64		s_size;             /* total size of fs in bytes */
	char		s_volume_name[16];  /* volume name */
	/* points to the location of pmfs_journal_t */
	__le64          s_journal_offset;
	/* points to the location of struct pmfs_inode for the inode table */
	__le64          s_inode_table_offset;

	__le64		s_start_dynamic;

	/* all the dynamic fields should go here */
	__le32		s_mtime;            /* mount time */
	__le32		s_wtime;            /* write time */

	/* fields for fast mount support. Always keep them together */
	__le64		s_num_blocknode_allocated;
	__le64		s_num_free_blocks;
	__le32		s_inodes_count;
	__le32		s_free_inodes_count;
	__le32		s_inodes_used_count;
	__le32		s_free_inode_hint;
};

/* The root inode follows immediately after the redundant super block */
#define PMFS_ROOT_INO (PMFS_INODE_SIZE)
#define PMFS_BLOCKNODE_INO (PMFS_ROOT_INO + PMFS_INODE_SIZE)

#endif /* PMFS_DEF_H_ */
