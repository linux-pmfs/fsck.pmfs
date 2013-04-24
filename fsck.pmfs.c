/*
 * Copyright 2013 Intel Corporation
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2. See the file COPYING for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "types.h"
#include "crc16.h"
#include "pmfs_def.h"

/*
 * The exit codes are defined to be consistent with other fsck implementations.
 */
enum exit_codes {
    STATUS_OK = 0,
    STATUS_ERROR = 4,
    STATUS_FAILURE = 8,
    STATUS_USAGE = 16,
};

#define VERSION 1


/*
 * blocksize is stored in the file system, but it is always set to 4096
 * and for efficiency this checker depends on that value.
 * This program could be easily changed to use the value in the file
 * system if necessary.
 */
#define BLOCKSIZE 4096
#define INODES_PER_BLOCK (BLOCKSIZE / PMFS_INODE_SIZE)
#define PTRS_PER_BLOCK (BLOCKSIZE / sizeof (u64))
#define BLOCKNODES_PER_BLOCK (BLOCKSIZE / sizeof (struct pmfs_blocknode))

#define PMFS_MINIMUM_JOURNAL_SIZE  (1ull << 16)


/* Local copy of some fields of the superblock. */
struct superblock {
    u64 size;
    u64 journal_offset;
    u64 inode_table_offset;
    // This blocksize field holds the size of the inode table's blocks
    // in units of 4096-byte blocks, not in bytes.
    u64 inode_table_blocksize;
};


struct pmfs_blocknode {
    u64 start, end;
};

struct block_list {
    struct block_list *next;
    struct pmfs_blocknode blocknode;
};


/* Convert file system fields to internal form. */
/* Surely this is a solved problem; what's the solution?
 * I tried leXX_to_cpu (which is used in the kernel), and
 * #include <endian.h>, which is documented to do what I need.
 * No dice. This solution works on x86. */
#define LE16(v) ((u16)(v))
#define LE32(v) ((u32)(v))
#define LE64(v) ((u64)(v))


static void parse_args(int argc, char **argv);
static void usage(FILE *);
static void version(void);
static time_t parse_time(const char *);

static void check_superblock(const struct pmfs_super_block *s);
static void check_journal(const struct pmfs_journal *journal);
static void check_inodes(const struct pmfs_super_block *s,
                         const struct pmfs_inode *inode_table);
static void check_allocation_list(const struct pmfs_super_block *s,
                                  const struct pmfs_inode *inode_table);
static void check_link_counts(const struct pmfs_inode *inode_table);
static void mark_allocated(u64 block, u32 count);

static void walk_inodes(u64 block, int height, unsigned index,
                void (*handler)(const struct pmfs_inode *inode, unsigned index),
                int mark);
static void check_inode(const struct pmfs_inode *inode, unsigned inode_index);
static void check_link_count(const struct pmfs_inode *inode, unsigned inode_index);

static u64 count_blocks(u64 block, int height, u64 blocksize);
static void check_directory(const struct pmfs_inode *ino, unsigned inode_index);
static void check_symlink(const struct pmfs_inode *ino, unsigned inode_index);

static void check(int sz, u64 val, u64 exp, const char *msg, ...)
    __attribute__((format(printf, 4, 5)));
static void check_range(int sz, u64 val, u64 min, u64 max, const char *msg, ...)
    __attribute__((format(printf, 5, 6)));
static bool check_non_null(u64 val, const char *msg, ...)
    __attribute__((format(printf, 2, 3)));
static void check_time(time_t t, const char *msg, ...)
    __attribute__((format(printf, 2, 3)));
static void check_uid(u32 uid, const char *msg, ...)
    __attribute__((format(printf, 2, 3)));
static void check_string(const char *s, int len, const char *msg, ...)
    __attribute__((format(printf, 3, 4)));
static void check_blocknode(const struct pmfs_blocknode *a,
                            const struct pmfs_blocknode *b,
                            const char *msg, ...)
    __attribute__((format(printf, 3, 4)));

static void dump(const void *p, int size);


// Command line options
static const char *progname;
static int verbose;
static int use_backup_superblock = 0;
static u64 phys_addr = 0;
static time_t min_time, max_time;
static int allow_time_0 = 0;


static void *fs_base;
static int status = 0;
static struct superblock sb;
static unsigned inode_count;
static u16 *inode_link_counts;
static struct block_list *allocation_list;

int main(int argc, char **argv)
{
    /* default min time is Jan 1, 2013 */
    struct tm min_tm = { 0, 0, 0, 1, 0, 113, 0, 0, 0 };
    min_time = mktime(&min_tm);
    max_time = time(NULL);

    parse_args(argc, argv);

    if (verbose) {
        printf("min time %08lx %s", min_time, ctime(&min_time));
        printf("max time %08lx %s", max_time, ctime(&max_time));
    }

    int fd = open("/dev/mem", 0);
    if (fd < 0) {
        perror("/dev/mem");
        exit(STATUS_FAILURE);
    }

    /* First map only the superblock and check it. */
    fs_base = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, phys_addr);
    if (fs_base == MAP_FAILED) {
        perror("mmap");
        exit(STATUS_FAILURE);
    }

    const struct pmfs_super_block *s =
        use_backup_superblock ? fs_base + PMFS_SB_SIZE : fs_base;

    check_superblock(s);

    /* Now that the superblock has been checked, use the size
     * in the superblock to map the whole file system. */
    munmap(fs_base, 4096);
    fs_base = mmap(NULL, sb.size, PROT_READ, MAP_SHARED, fd, phys_addr);
    if (fs_base == NULL) {
        perror("mmap");
        exit(STATUS_FAILURE);
    }
    s = fs_base;

    check_journal(fs_base + sb.journal_offset);
    check_inodes(s, fs_base + sb.inode_table_offset);
    check_allocation_list(s, fs_base + sb.inode_table_offset);
    check_link_counts(fs_base + sb.inode_table_offset);

    munmap(fs_base, sb.size);

    return status;
}

static void parse_args(int argc, char **argv)
{
    int c;
    opterr = 0;
    progname = argv[0] != NULL ? argv[0] : "fsck.pmfs";
    while ((c = getopt(argc, argv, "+A:t:T:bfhnvyV")) != -1) {
        switch (c) {
            case 'A': {
                char *e;
                phys_addr = strtoull(optarg, &e, 0);
                if (*e) {
                    usage(stderr);
                    exit(STATUS_USAGE);
                }
                break;
            }
            case 't': {
                time_t t = parse_time(optarg);
                if (t == 0)
                    allow_time_0 = 1;
                else
                    min_time = t;
                break;
            }
            case 'T': max_time = parse_time(optarg); break;
            case 'b': use_backup_superblock = 1; break;
            case 'f': break;
            case 'h': usage(stdout); exit(STATUS_OK);
            case 'n': break;
            case 'v': verbose++; break;
            case 'y': break;
            case 'V': version(); exit(STATUS_OK);
            default:  usage(stderr); exit(STATUS_USAGE);
        }
    }

    if (phys_addr == 0) {
        usage(stderr);
        exit(STATUS_USAGE);
    }
}

static void usage(FILE *f)
{
    fprintf(f, "Usage: %s [-bfhnvyV] [-t min-time] [-T max-time] -A physaddr\n", progname);
}

static void version(void)
{
    printf("%s version %u\n", progname, VERSION);
}


static time_t parse_time(const char *s)
{
    char *e;
    time_t t = strtoull(s, &e, 0);
    if (*e) {
        usage(stderr);
        exit(STATUS_USAGE);
    }
    return t;
}


static void check_superblock(const struct pmfs_super_block *s)
{
    uint sb_size = offsetof(struct pmfs_super_block, s_start_dynamic);

    if (verbose) {
        printf("Checking superblock\n");
        if (verbose > 2)
            dump(s, sizeof *s);
    }

    check(16, LE16(s->s_magic), PMFS_SUPER_MAGIC, "superblock magic number");
    check(16, LE16(s->s_sum),
          crc16(~0, (u8 *)s + sizeof (u16), sb_size - sizeof (u16)),
          "superblock checksum");
    u32 blocksize = LE32(s->s_blocksize);
    check(32, blocksize, BLOCKSIZE, "superblock block size");
    check(32, INODES_PER_BLOCK, blocksize / PMFS_INODE_SIZE, "inodes per block");
    check(32, PTRS_PER_BLOCK, blocksize / sizeof (u64), "pointers per block");
    sb.size = LE64(s->s_size);
    check_range(64, sb.size, PMFS_MINIMUM_JOURNAL_SIZE + 3 * blocksize,
                0x40000000000ull, "file system size");

    /* If any of the above checks fail, we cannot continue checking. */
    if (status != STATUS_OK)
        exit(status);

    check_time(LE32(s->s_mtime), "superblock mtime");
    check_time(LE32(s->s_wtime), "superblock wtime");
    check_string(s->s_volume_name, sizeof (s->s_volume_name),
                 "superblock volume name");

    sb.journal_offset = LE64(s->s_journal_offset);
    sb.inode_table_offset = LE64(s->s_inode_table_offset);

    if (sb.journal_offset < sb.inode_table_offset) {
        check_range(64, sb.journal_offset,
                    sizeof (struct pmfs_super_block),
                    sb.inode_table_offset - sizeof (struct pmfs_journal),
                    "journal");
        check_range(64, sb.inode_table_offset,
                    sb.journal_offset + sizeof (struct pmfs_journal),
                    blocksize - sizeof (struct pmfs_inode),
                    "inode table");
    }
    else {
        check_range(64, sb.journal_offset,
                    sb.inode_table_offset + sizeof (struct pmfs_inode),
                    blocksize - sizeof (struct pmfs_journal),
                    "journal");
        check_range(64, sb.inode_table_offset,
                    sizeof (struct pmfs_super_block),
                    sb.journal_offset - sizeof (struct pmfs_inode),
                    "inode table");
    }

    void *alt = (void *)((u64)s ^ PMFS_SB_SIZE);
    if (memcmp(s, alt, sb_size) != 0) {
        if (verbose)
            printf("ERROR: ");
        printf("secondary superblock doesn't match primary superblock\n");
        if (verbose) {
            dump(s, sizeof *s);
            dump(alt, sizeof *s);
        }
    }

    mark_allocated(0, 1);
}

static void check_journal(const struct pmfs_journal *j)
{
    if (verbose) {
        printf("Checking journal\n");
        if (verbose > 2)
            dump(j, sizeof *j);
    }

    u64 base = LE64(j->base);
    u32 size = LE32(j->size);
    u32 head = LE32(j->head);
    u32 tail = LE32(j->tail);
    check_range(64, base, BLOCKSIZE, sb.size, "journal base");
    check_range(64, size, 1, sb.size, "journal size");
    check_range(64, base + size, 0, sb.size, "journal range");
    check(16, LE16(j->pad), 0, "journal pad");
    check(16, LE16(j->redo_logging), 0, "journal redo logging");
    check_range(32, head, 0, size, "head");
    check_range(32, tail, 0, size, "tail");
    check(32, tail, head, "tail");

    mark_allocated(base, size / BLOCKSIZE);
}

static void check_inodes(const struct pmfs_super_block *s,
                         const struct pmfs_inode *inode_table)
{
    if (verbose) {
        printf("Checking inode root\n");
        if (verbose > 2)
            dump(inode_table, sizeof *inode_table);
    }

    check_range(8, inode_table->height, 0, 3, "inode table height");

    sb.inode_table_blocksize = 1ull << 9 * inode_table->i_blk_type;
    u64 size = LE64(inode_table->i_size);
    u64 blocks = LE64(inode_table->i_blocks);
    u64 expected_size = blocks * BLOCKSIZE;
    u64 max_blocks = (1ull << (inode_table->height * META_BLK_SHIFT))
                         * sb.inode_table_blocksize;
    check_range(64, blocks, 1, sb.size / BLOCKSIZE - 2, "inode table blocks");
    check_range(64, blocks, 1, max_blocks, "inode table blocks");
    check(64, size, expected_size, "inode table size");
    check(64, LE64(inode_table->i_next_truncate), 0, "truncate list");

    inode_count = (unsigned)(size / PMFS_INODE_SIZE);
    inode_link_counts = calloc(inode_count, sizeof (u16));

    // Set expected link count for inode 2 to 1. This inode contains
    // the block map but is not referenced by any directory entry.
    if (s->s_num_blocknode_allocated != 0)
        inode_link_counts[2] = 1;

    u64 inode_root = LE64(inode_table->root);
    if (check_non_null(inode_root, "inode table root"))
        walk_inodes(inode_root, inode_table->height, 0, check_inode, 1);
}

static void check_link_counts(const struct pmfs_inode *inode_table)
{
    if (verbose)
        printf("Checking link counts\n");

    walk_inodes(LE64(inode_table->root), inode_table->height, 0, check_link_count, 0);
}


static unsigned ipow(unsigned b, unsigned e)
{
    unsigned r = 1;
    while (e-- > 0)
        r *= b;
    return r;
}

static unsigned ilog10(unsigned n)
{
    int r = 0;
    while (n >= 10)
        n /= 10, r++;
    return r;
}

static void walk_inodes(u64 block, int height, unsigned index,
                void (*handler)(const struct pmfs_inode *inode, unsigned index),
                int mark)
{
    if (verbose > 2)
        dump(fs_base + block, BLOCKSIZE);

    if (height > 0)
    {
        if (mark)
            mark_allocated(block, 1);

        u64 *p = fs_base + block;
        int h = height - 1;
        unsigned w = ipow(PTRS_PER_BLOCK, h) * INODES_PER_BLOCK;
        int i;
        for (i = 0; i < PTRS_PER_BLOCK; i++)
            if (p[i] != 0)
                walk_inodes(p[i], h, index + i*w, handler, mark);
    }
    else {
        if (mark)
            mark_allocated(block, sb.inode_table_blocksize);

        void *p = fs_base + block;
        u64 i = index == 0 ? 1 : 0;
        for (; i < INODES_PER_BLOCK * sb.inode_table_blocksize; i++)
            (*handler)(p + i*PMFS_INODE_SIZE, index + i);
    }
}


static void check_inode(const struct pmfs_inode *ino, unsigned inode_index)
{
    if (ino->i_links_count == 0 && ino->i_dtime == 0)
        return;

    if (verbose) {
        printf("Checking inode %u\n", inode_index);
        if (verbose > 2)
            dump(ino, sizeof *ino);
    }

    u64 root = LE64(ino->root);

    if (ino->i_links_count == 0) {
        check(64, root, 0, "inode %u root", inode_index);
        check_time(LE32(ino->i_dtime), "inode %u dtime", inode_index);
        return;
    }

    check_range(8, ino->height, 0, 3, "inode %u height", inode_index);
    check_range(8, ino->i_blk_type, 0, 2, "inode %u block type", inode_index);
    if (LE32(ino->i_flags) & ~0x200380ff != 0) {
        printf("inode %u flags %08lx, unexpected bits %08lx\n",
               inode_index, LE32(ino->i_flags), LE32(ino->i_flags) & ~0x200380ff);
        status |= STATUS_ERROR;
    }

    // This blocksize variable holds the size of the file's blocks
    // in units of 4096-byte blocks, not in bytes.
    u64 blocksize = 1ull << 9 * ino->i_blk_type;
    u64 size = LE64(ino->i_size);
    u64 blocks = LE64(ino->i_blocks);
    if (blocks > 0) {
        u64 max_size = blocks * BLOCKSIZE;
        u64 max_blocks = (1ull << (ino->height * META_BLK_SHIFT)) * blocksize;
        check_range(64, blocks, 0, sb.size / BLOCKSIZE - 2, "inode %u blocks", inode_index);
        check_range(64, blocks, 0, max_blocks, "inode %u blocks", inode_index);
        check_range(64, size, 0, max_size, "inode %u size", inode_index);
    }
    else {
        check(64, size, 0, "inode %u size", inode_index);
    }

    u64 block_count = root != 0 ? count_blocks(root, ino->height, blocksize) : 0;
    check(64, blocks, block_count * blocksize, "inode %u actual blocks", inode_index);

    check_range(16, LE16(ino->i_links_count), 1, 0xffff, "inode %u link count", inode_index);
    check_time(LE32(ino->i_mtime), "inode %u mtime", inode_index);
    check_time(LE32(ino->i_ctime), "inode %u ctime", inode_index);
    check(32, LE32(ino->i_dtime), 0, "inode %u dtime", inode_index);
    check_time(LE32(ino->i_atime), "inode %u atime", inode_index);
    check(64, LE64(ino->i_xattr), 0, "inode %u xattr", inode_index);

    check_uid(LE32(ino->i_uid), "inode %u uid", inode_index);
    check_uid(LE32(ino->i_gid), "inode %u gid", inode_index);

#if 0
    unsigned expected_height;
    if (size <= BLOCKSIZE * blocksize * (1ull << 0 * META_BLK_SHIFT))
        expected_height = 0;
    else if (size <= BLOCKSIZE * blocksize * (1ull << 1 * META_BLK_SHIFT))
        expected_height = 1;
    else if (size <= BLOCKSIZE * blocksize * (1ull << 2 * META_BLK_SHIFT))
        expected_height = 2;
    else
        expected_height = 3;
    check(8, ino->height, expected_height, "inode %u expected height", inode_index);

    if (blocks > 0) {
        check_range(64, size, BLOCKSIZE * (blocks - 1) + 1, BLOCKSIZE * blocks,
                    "inode %u expected size", inode_index);
    }
#endif

    switch (LE16(ino->i_mode) & S_IFMT)
    {
        case S_IFDIR: check_directory(ino, inode_index); break;
        case S_IFLNK: check_symlink(ino, inode_index); break;
    }
}

static u64 count_blocks(u64 block, int height, u64 blocksize)
{
    if (height == 0) {
        mark_allocated(block, blocksize);
        return 1;
    }

    mark_allocated(block, 1);

    u64 count = 0;
    u64 *p = fs_base + block;
    int h = height - 1;
    int i;
    for (i = 0; i < PTRS_PER_BLOCK; i++)
        if (p[i] != 0)
            count += count_blocks(p[i], h, blocksize);
    return count;
}

struct tree {
    u64 b[3];
    int height;
    u64 i[3];
};

static void init_tree(struct tree *tree, u64 root, int height)
{
    int h;
    tree->height = height;
    tree->b[0] = root;
    tree->i[0] = 0;
    for (h = 1; h < height; h++) {
        tree->b[h] = *(u64 *)(fs_base + tree->b[h-1]);
        tree->i[h] = 0;
    }
}

static u64 next_block(struct tree *tree)
{
    if (tree->height == 0) {
        if (tree->i[0]++ == 0)
            return tree->b[0];
        else
            return 0;
    }
    int h = tree->height - 1;
    u64 b = ((u64 *)(fs_base + tree->b[h]))[tree->i[h]];
    if (++tree->i[h] == PTRS_PER_BLOCK) {
        for (h-- ; h >= 0; h--) {
            if (++tree->i[h] < PTRS_PER_BLOCK)
                break;
        }
        if (h < 0) {
            tree->height = 0;
        }
        else {
            for (h++; h < tree->height; h++) {
                tree->b[h] = ((u64 *)(fs_base + tree->b[h-1]))[tree->i[h-1]];
                tree->i[h] = 0;
            }
        }
    }
    return b;
}

static void check_directory(const struct pmfs_inode *ino, unsigned inode_index)
{
    if (verbose)
        printf("Checking directory %u\n", inode_index);

    u64 size = LE64(ino->i_size);
    u64 blocks = LE64(ino->i_blocks);
    u64 max_size = blocks * BLOCKSIZE;
    check(64, size, max_size, "dir %u size", inode_index);
    check_range(64, size, 1, max_size, "dir %u size", inode_index);

    struct tree tree;
    init_tree(&tree, LE64(ino->root), ino->height);
    unsigned o = 0;
    u64 b;
    while ((b = next_block(&tree)) != 0) {
        u8 *p = fs_base + b;
        if (verbose > 2)
            dump(p, BLOCKSIZE);
        unsigned bo = 0;
        while (bo < BLOCKSIZE) {
            const struct pmfs_direntry *d = (const struct pmfs_direntry *)&p[bo];

            u64 i = LE64(d->ino);
            u16 de_len = LE16(d->de_len);
            if (i != 0) {
                u64 ix = i / PMFS_INODE_SIZE;
                if ((i & (PMFS_INODE_SIZE - 1)) != 0 || ix >= inode_count) {
                    printf("dir %u entry %x inode number %08llx (inode_count=%x)\n", inode_index, o, i, inode_count);
                    status |= STATUS_ERROR;
                }
                else {
                    inode_link_counts[ix]++;
                }

                check_range(8, d->name_len, 1, PMFS_NAME_LEN, "dir %u entry %x name_len", inode_index, o);
                check_range(16, de_len, d->name_len + 12, BLOCKSIZE - bo, "dir %u entry %x de_len", inode_index, o);
                check_string(d->name, d->name_len, "dir %u entry %x name", inode_index, o);
            }
            else {
                check_range(16, de_len, 12, BLOCKSIZE - bo, "dir %u entry %x de_len", inode_index, o);
            }

            bo += de_len;
            o += de_len;
        }
    }
}

static void check_symlink(const struct pmfs_inode *ino, unsigned inode_index)
{
    check(8, ino->height, 0, "symlink %u height", inode_index);
    check(64, LE64(ino->i_blocks), 1, "symlink %u blocks", inode_index);
    u64 size = LE64(ino->i_size);
    void *data = fs_base + LE64(ino->root);
    check_string(data, size, "symlink %u name", inode_index);
}


static void check_link_count(const struct pmfs_inode *ino, unsigned inode_index)
{
    unsigned link_count = inode_link_counts[inode_index];
    check(16, LE16(ino->i_links_count), link_count, "inode %u link count", inode_index);
}


static void check(int sz, u64 val, u64 exp, const char *msg, ...)
{
    if (val != exp) {
        if (verbose)
            printf("ERROR: ");
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %0*llx, expected %0*llx\n", sz/4, val, sz/4, exp);
        status |= STATUS_ERROR;
    }
    else if (verbose > 1) {
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %0*llx\n", sz/4, val);
    }
}

static void check_range(int sz, u64 val, u64 min, u64 max, const char *msg, ...)
{
    if (val < min || val > max) {
        if (verbose)
            printf("ERROR: ");
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %0*llx, expected %0*llx .. %0*llx\n", sz/4, val, sz/4, min, sz/4, max);
        status |= STATUS_ERROR;
    }
    else if (verbose > 1) {
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %0*llx\n", sz/4, val);
    }
}

static bool check_non_null(u64 val, const char *msg, ...)
{
    if (val == 0) {
        if (verbose)
            printf("ERROR: ");
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" is NULL\n");
        status |= STATUS_ERROR;
        return false;
    }
    else if (verbose > 1) {
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %016llx\n", val);
    }
    return true;
}

static void check_time(time_t t, const char *msg, ...)
{
    if ((t < min_time || t > max_time) && !(allow_time_0 && t == 0)) {
        if (verbose)
            printf("ERROR: ");
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %08lx, expected %08lx .. %08lx\n", t, min_time, max_time);
        status |= STATUS_ERROR;
    }
    else if (verbose > 1) {
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %08lx\n", t);
    }
}

static void check_uid(u32 uid, const char *msg, ...)
{
    if (uid != 0 && uid != 1000) {
        if (verbose)
            printf("ERROR: ");
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %08lx, expected 0 or 1000\n", uid);
        status |= STATUS_ERROR;
    }
    else if (verbose > 1) {
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %08lx\n", uid);
    }
}

static void check_string(const char *s, int len, const char *msg, ...)
{
    int bad = 0;
    int end = 0;
    int extra = 0;
    int i;
    for (i = 0; i < len; i++) {
        if (s[i] == '\0')
            end = 1;
        else if (!isascii(s[i]) || !isprint(s[i]))
            bad++;
        else if (end)
            extra++;
    }
    if (bad > 0 || extra > 0) {
        if (verbose)
            printf("ERROR: ");
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        if (bad > 0)
            printf(" %d non-ascii characters", bad);
        if (extra > 0)
            printf(" %d characters after null", extra);
        printf("\n");
    }
    else if (verbose > 1) {
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %.*s\n", len, s);
    }

}

static void check_blocknode(const struct pmfs_blocknode *a,
                            const struct pmfs_blocknode *b,
                            const char *msg, ...)
{
    if (a->start != b->start || a->end != b->end) {
        if (verbose)
            printf("ERROR: ");
        va_list args;
        va_start(args, msg);
        vprintf(msg, args);
        va_end(args);
        printf(" %08llx - %08llx, expected %08llx - %08llx\n", a->start, a->end, b->start, b->end);
        status |= STATUS_ERROR;
    }
}


static void mark_allocated(u64 block, u32 count)
{
    u64 start = block / BLOCKSIZE;
    u64 end = start + count - 1;
    struct block_list **q = &allocation_list;

    while (1) {
        struct block_list *p = *q;

        if (p == NULL || end + 1 < p->blocknode.start) {
            p = malloc(sizeof (struct block_list));
            p->blocknode.start = start;
            p->blocknode.end = end;
            p->next = *q;
            *q = p;
            return;
        }

        if (end + 1 == p->blocknode.start) {
            p->blocknode.start = start;
            return;
        }

        if (start == p->blocknode.end + 1) {
            struct block_list *next= p->next;
            if (next != NULL && end + 1 == next->blocknode.start) {
                p->blocknode.end = next->blocknode.end;
                p->next = next->next;
                free(next);
            }
            else {
                p->blocknode.end = end;
            }
            return;
        }

        q = &p->next;
    }
}

static void check_allocation_list(const struct pmfs_super_block *s,
                                  const struct pmfs_inode *inode_table)
{
    int i;

    if (verbose > 1) {
        const struct block_list *p;
        printf("Computed allocation list:");
        for (p = allocation_list; p != NULL; p = p->next)
            printf(" %llu-%llu", p->blocknode.start, p->blocknode.end);
        printf("\n");
    }

    u64 num_blocknodes = LE64(s->s_num_blocknode_allocated);

    u64 inode_base = LE64(inode_table->root);
    if (!check_non_null(inode_base, "inode table root"))
        return;
    for (i = 0; i < inode_table->height; i++) {
        inode_base = LE64(*(u64 *)(fs_base + inode_base));
        if (!check_non_null(inode_base, "inode table level %d", i + 1))
            return;
    }

    const struct pmfs_inode *ino = fs_base + inode_base + PMFS_BLOCKNODE_INO;
    struct tree tree;
    unsigned n;
    u64 b;

    if (verbose > 1) {
        printf("Stored allocation list:");
        init_tree(&tree, LE64(ino->root), ino->height);
        n = 0;
        while ((b = next_block(&tree)) != 0) {
            const struct pmfs_blocknode *bn = fs_base + b;
            for (i = 0; i < BLOCKNODES_PER_BLOCK && n < num_blocknodes; i++, n++)
                printf(" %llu-%llu", bn[i].start, bn[i].end);
        }
        printf("\n");
    }

    const struct block_list *p = allocation_list;
    init_tree(&tree, LE64(ino->root), ino->height);
    n = 0;
    while ((b = next_block(&tree)) != 0) {
        const struct pmfs_blocknode *bn = fs_base + b;
        for (i = 0; i < BLOCKNODES_PER_BLOCK && n < num_blocknodes; i++, n++) {
            check_blocknode(&bn[i], &p->blocknode, "blocknode %u", n);
            p = p->next;
        }
    }
}


static void dump(const void *m, int size)
{
    const unsigned *p = m;
    int i, j;
    int w = ilog10(size) + 1;
    for (i = 0; i < size; i += 16) {
        printf("%*d:", w, i);
        for (j = 0; j < 16 && i + j < size; j += 4)
            printf(" %08x", p[(i+j)/4]);
        printf("\n");
    }
    printf("\n");
}
