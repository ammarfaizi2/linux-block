/*
 * A frontend cache for a block device. The purpose is to speedup a
 * fairly random but repeated read work load, like the boot of a system.
 *
 * When run in priming mode, fcache allocates and writes data read from
 * the source drive to our extent cache in the order in which they are
 * accessed. When later run in non-priming mode, data accessed in the same
 * order will be linearly available in the cache.
 *
 * Performance when priming is slower than non-fcache usage would be. If
 * the fcache is located on another disk, the hit should be small. If the
 * the fcache is located on the same disk (another partition), it runs
 * at about half the speed. Non-priming performance should be fairly
 * similar on same/other disk.
 *
 * On-disk format is as follows:
 *	Block0:		header
 *	Block1..X	extent maps
 *	BlockX+1..Y	extent data
 *
 * Copyright (C) 2006 Jens Axboe <axboe@suse.de>
 *
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/blkdev.h>
#include <linux/prio_tree.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/rbtree.h>

#define FCACHE_MAGIC	0x61786663
#define FCACHE_VERSION	0x03

#define FCACHE_HEADER_BLOCK	0
#define FCACHE_EXTENT_BLOCK	1

/*
 * If some extents see repeated overwrites, just get rid of them.
 */
#define FCACHE_MAX_OVERWRITES	5
#define FCACHE_OVERWRITE_TIME	HZ

#undef FCACHE_PAGES_PROTECTED

struct fcache_dev {
	struct block_device *bdev;
	struct block_device *fs_bdev;
	make_request_fn *mfn;
	struct prio_tree_root prio_root;
	struct list_head fe_list;
	unsigned long next_cache_block;
	unsigned long nr_extents;
	unsigned long max_extents;
	unsigned int old_bs;
	spinlock_t lock;

	sector_t cache_start_sector;
	unsigned long cache_blocks;
	sector_t fs_start_sector;
	sector_t fs_sectors;

	unsigned long flags;
	int priming;
	int serial;
	int chop_ios;

	struct list_head list;
	struct work_struct work;

	struct fcache_extent *last_fe;

	struct rb_root rb_root;		/* sorted pcache pages */

	/*
	 * stats
	 */
	unsigned int ios[2];
	unsigned int hits;
	unsigned int misses;
	unsigned int partial;
	unsigned int overwrites;
	unsigned int extent_merges;
	unsigned int extent_drops;
	unsigned long pcache_kb;
	unsigned int pcache_hits;
};

enum {
	FDEV_F_DOWN = 0,
};

static struct fcache_dev fcache_dev;

static int disable;
module_param(disable, int, 0444);
static int pcache_disable;
module_param(pcache_disable, int, 0444);

struct fcache_endio_data {
	struct fcache_dev *fdev;
	sector_t fs_sector;
	unsigned int fs_size;
	sector_t cache_sector;
	atomic_t completions;
	struct bio *bio;
	int io_error;
	struct list_head list;
};

/*
 * Maps a file system block to the fcache
 */
struct fcache_extent {
	sector_t fs_sector;	/* real device offset */
	unsigned int fs_size;	/* extent length */
	sector_t cache_sector;	/* cache device offset */

	struct prio_tree_node prio_node;	/* fs_sector sorted */
	struct list_head fe_list;		/* cache_sector sorted */

	struct page **pages;	/* prefetch window pages */
	int numpages;
	int readpages;

	unsigned int valid;	/* extent is valid */
	unsigned int overwrites;	/* number of times we wrote over */
	unsigned long ow_time;	/* overwrite time */
};

/*
 * On-disk representation of fcache_extent.
 */
struct fcache_ondisk_extent {
	__be64 fs_sector;
	__be64 cache_sector;
	__be32 fs_size;
};

/*
 * Header on fcache device - will take up the first page of data, so
 * plenty of room to go around.
 */
struct fcache_header {
	u32 magic;		/* fcache magic */
	u32 version;		/* fcache version */
	u32 nr_extents;		/* nr of extents in cache */
	u32 max_extents;	/* max nr of extents available */
	u32 serial;		/* fs and cache serial */
	u32 extent_offset;	/* where extents start */
	u64 fs_start_sector;	/* where fs starts */
	u64 fs_sectors;		/* how big fs is */
	char fs_dev[BDEVNAME_SIZE];	/* fs partition */
	u64 cache_blocks;	/* number of blocks in cache */
	u64 cache_blocks_used;	/* used blocks in cache */
};

#define FBLOCK_SHIFT (PAGE_SHIFT - 9)
#define FBLOCK_SIZE (1 << FBLOCK_SHIFT)
#define FBLOCK_MASK (FBLOCK_SIZE - 1)

static struct kmem_cache *fcache_slab;
static struct kmem_cache *fcache_fed_slab;
static mempool_t *fed_pool;
static struct workqueue_struct *fcache_workqueue;

static void __fcache_fe_drop(struct fcache_extent *fe);

static int fcache_rw_page_endio(struct bio *bio, unsigned int bytes, int err)
{
	if (bio->bi_size)
		return 1;

	complete(bio->bi_private);
	return 0;
}

/*
 * Writes out a page of data and waits for it to complete.
 */
static int fcache_rw_page(struct fcache_dev *fdev, sector_t index,
			  struct page *page, int rw)
{
	DECLARE_COMPLETION(wait);
	struct bio *bio;
	int ret = 0;

	bio = bio_alloc(GFP_KERNEL, 1);

	bio->bi_sector = index << FBLOCK_SHIFT;
	bio->bi_bdev = fdev->bdev;
	bio->bi_rw |= (1 << BIO_RW_SYNC);
	bio->bi_end_io = fcache_rw_page_endio;
	bio->bi_private = &wait;

	bio_add_page(bio, page, PAGE_SIZE, 0);
	submit_bio(rw, bio);

	wait_for_completion(&wait);

	if (!bio_flagged(bio, BIO_UPTODATE))
		ret = -EIO;

	bio_put(bio);
	return ret;
}

static inline void fcache_fill_header(struct fcache_dev *fdev,
				      struct fcache_header *header,
				      unsigned int nr_extents)
{
	/*
	 * See how many pages we need for extent headers, then we know where
	 * to start putting data. Assume worst case of 1 page per extent, and
	 * reserve the first page for the header.
	 */

	header->magic = FCACHE_MAGIC;
	header->version = FCACHE_VERSION;
	header->nr_extents = nr_extents;
	header->max_extents = ((fdev->cache_blocks - 1) * PAGE_SIZE) / (PAGE_SIZE - sizeof(struct fcache_ondisk_extent));
	header->serial = fdev->serial;

	header->extent_offset = 1 + (header->max_extents * sizeof(struct fcache_ondisk_extent) / PAGE_SIZE);

	header->fs_start_sector = fdev->fs_start_sector;
	header->fs_sectors = fdev->fs_sectors;
	bdevname(fdev->fs_bdev, header->fs_dev);
	header->cache_blocks = fdev->cache_blocks;
	header->cache_blocks_used = fdev->next_cache_block;
}

static int fcache_write_new_header(struct fcache_dev *fdev)
{
	struct fcache_header *header;
	struct page *page;
	int ret;

	page = alloc_page(GFP_HIGHUSER);
	if (unlikely(!page))
		return -ENOMEM;

	header = kmap_atomic(page, KM_USER0);
	clear_page(header);
	fcache_fill_header(fdev, header, 0);
	fdev->next_cache_block = header->extent_offset;
	fdev->max_extents = header->max_extents;
	kunmap_atomic(header, KM_USER0);

	printk("fcache: new header: first block %lu, max %lu\n",
				fdev->next_cache_block, fdev->max_extents);
	ret = fcache_rw_page(fdev, FCACHE_HEADER_BLOCK, page, WRITE);
	__free_page(page);
	return ret;
}

static void fcache_free_links(struct fcache_dev *fdev)
{
	struct fcache_extent *fe;
	int i;

	while (!list_empty(&fdev->fe_list)) {
		fe = list_entry(fdev->fe_list.next, struct fcache_extent, fe_list);

		list_del_init(&fe->fe_list);

		for (i = 0; i < fe->numpages; i++) {
			wait_on_page_locked(fe->pages[i]);
			__free_page(fe->pages[i]);
		}

		prio_tree_remove(&fdev->prio_root, &fe->prio_node);
		kmem_cache_free(fcache_slab, fe);
	}
}

/*
 * First clear the header, write extents, then write real header.
 */
static int fcache_write_extents(struct fcache_dev *fdev)
{
	struct fcache_header *header;
	sector_t index, sectors;
	unsigned int nr_extents, this_extents;
	struct fcache_extent *fe;
	struct prio_tree_iter iter;
	struct prio_tree_node *node;
	struct page *page;
	void *p;
	int ret;

	page = alloc_page(GFP_KERNEL);
	if (unlikely(!page))
		return -ENOMEM;

	header = page_address(page);
	clear_page(header);
	fcache_fill_header(fdev, header, 0);
	ret = fcache_rw_page(fdev, FCACHE_HEADER_BLOCK, page, WRITE);
	if (ret)
		goto err;

	/*
	 * Now write the extents in page size chunks.
	 */
	p = page_address(page);
	clear_page(p);
	index = FCACHE_EXTENT_BLOCK;
	sectors = 0;
	this_extents = nr_extents = 0;

	prio_tree_iter_init(&iter, &fdev->prio_root, 0, ULONG_MAX);

	do {
		struct fcache_ondisk_extent *foe;

		node = prio_tree_next(&iter);
		if (!node)
			break;

		fe = prio_tree_entry(node, struct fcache_extent, prio_node);
		if (!fe->valid)
			continue;

		foe = p;
		foe->fs_sector = cpu_to_be64(fe->fs_sector);
		foe->cache_sector = cpu_to_be64(fe->cache_sector);
		foe->fs_size = cpu_to_be32(fe->fs_size);

		nr_extents++;
		this_extents++;
		sectors += fe->fs_size >> 9;
		p += sizeof(*foe);
		if ((this_extents + 1) * sizeof(*foe) > PAGE_SIZE) {
			ret = fcache_rw_page(fdev, index, page, WRITE);
			if (ret)
				break;

			this_extents = 0;
			index++;
			p = page_address(page);
		}
	} while (1);

	if (this_extents)
		ret = fcache_rw_page(fdev, index, page, WRITE);

	fdev->nr_extents = nr_extents;
	printk("fcache: wrote %d extents, holding %llu sectors of data\n",
				nr_extents, (unsigned long long) sectors);
err:
	__free_page(page);
	return ret;
}

static int fcache_write_header(struct fcache_dev *fdev)
{
	struct page *page;
	int ret;

	page = alloc_page(GFP_KERNEL);
	if (unlikely(!page))
		return -ENOMEM;

	ret = fcache_rw_page(fdev, FCACHE_HEADER_BLOCK, page, READ);
	if (!ret) {
		struct fcache_header *header = page_address(page);

		fcache_fill_header(fdev, header, fdev->nr_extents);
		ret = fcache_rw_page(fdev, FCACHE_HEADER_BLOCK, page, WRITE);
		printk("fcache: wrote header (extents=%lu,serial=%d)\n",
						fdev->nr_extents, fdev->serial);
	}

	__free_page(page);
	return ret;
}

static void fcache_fe_link(struct fcache_dev *fdev, struct fcache_extent *fe)
{
	struct fcache_extent *__fe;
	struct list_head *entry;

	entry = &fdev->fe_list;
	while ((entry = entry->prev) != &fdev->fe_list) {
		__fe = list_entry(entry, struct fcache_extent, fe_list);
		if (__fe->cache_sector < fe->cache_sector)
			break;
	}

	list_add(&fe->fe_list, entry);
}

static int fcache_tree_link(struct fcache_dev *fdev, struct fcache_extent *fe)
{
	struct prio_tree_node *node = &fe->prio_node;
	struct prio_tree_node *ret;

	node->start = fe->fs_sector;
	node->last = fe->fs_sector + (fe->fs_size >> 9) - 1;

	ret = prio_tree_insert(&fdev->prio_root, node);
	if (ret == node)
		return 0;

	return 1;
}

static void fcache_tree_reposition(struct fcache_dev *fdev,
				   struct fcache_extent *fe)
{
	struct prio_tree_node *node = &fe->prio_node;
	unsigned long flags;

	spin_lock_irqsave(&fdev->lock, flags);
	prio_tree_remove(&fdev->prio_root, node);
	node->start = fe->fs_sector;
	node->last = fe->fs_sector + (fe->fs_size >> 9) - 1;

	prio_tree_insert(&fdev->prio_root, node);
	spin_unlock_irqrestore(&fdev->lock, flags);
}

static struct fcache_extent *fcache_get_fe(gfp_t gfp_mask)
{
	struct fcache_extent *fe = kmem_cache_alloc(fcache_slab, gfp_mask);

	if (fe) {
		memset(fe, 0, sizeof(*fe));
		INIT_PRIO_TREE_NODE(&fe->prio_node);
		INIT_LIST_HEAD(&fe->fe_list);
		fe->valid = 1;
		fe->ow_time = -1;
	}

	return fe;
}

#define MAX_FE	16

/*
 * Lookup the range of a given request in the prio tree. Used for both
 * looking up a range covering a read operation to be served from cache,
 * and to lookup potential conflicts from a new write with an existing
 * extent.
 */
static int fcache_lookup_extent(struct fcache_dev *fdev, sector_t offset,
				sector_t end_sector, struct fcache_extent **map)
{
	struct prio_tree_node *node;
	struct prio_tree_iter iter;
	int i = 0, need_lock;

	prio_tree_iter_init(&iter, &fdev->prio_root, offset, end_sector);

	/*
	 * We only need to lock, if we are priming. The prio tree does
	 * not change when in normal mode.
	 */
	need_lock = fdev->priming;
	if (need_lock)
		spin_lock_irq(&fdev->lock);

	do {
		struct fcache_extent *fe;

		node = prio_tree_next(&iter);
		if (!node)
			break;

		fe = prio_tree_entry(node, struct fcache_extent, prio_node);
		smp_wmb();
		if (fe->valid)
			map[i++] = fe;
	} while (i < MAX_FE);

	if (need_lock)
		spin_unlock_irq(&fdev->lock);

	return i;
}

/*
 * Our data write is done, now insert the fcache extents into the rbtree.
 */
static int fcache_instantiate_extent(struct fcache_dev *fdev,
				     struct fcache_endio_data *fed)
{
	struct fcache_extent *fe = fdev->last_fe;

	/*
	 * Don't instantiate an errored io.
	 */
	if (fed->io_error)
		return -EIO;

	/*
	 * Check if we can merge this extent with the previous one.
	 */
	if (fe && (fe->fs_sector + (fe->fs_size >> 9) == fed->fs_sector) &&
	    (fe->cache_sector + (fe->fs_size >> 9) == fed->cache_sector) &&
	    fe->valid) {
		fe->fs_size += fed->fs_size;
		fcache_tree_reposition(fdev, fe);
		fdev->nr_extents--;
		fdev->extent_merges++;
	} else {
		unsigned long flags;

		fe = fcache_get_fe(GFP_ATOMIC);
		if (unlikely(!fe))
			return -ENOMEM;

		fe->fs_sector = fed->fs_sector;
		fe->fs_size = fed->fs_size;
		fe->cache_sector = fed->cache_sector;

		spin_lock_irqsave(&fdev->lock, flags);
		if (!fcache_tree_link(fdev, fe)) {
			fcache_fe_link(fdev, fe);
			fdev->last_fe = fe;
		} else {
			fdev->nr_extents--;
			kmem_cache_free(fcache_slab, fe);
		}

		spin_unlock_irqrestore(&fdev->lock, flags);
	}

	return 0;
}

/*
 * Hang on to the bio and its pages - ideally we would want to ensure
 * that the page data doesn't change between calling this function and
 * fcache_put_bio_pages() as well...
 */
static void fcache_get_bio_pages(struct fcache_dev *fdev, struct bio *bio)
{
	/*
	 * Currently stubbed out, as we cannot end the bio read before
	 * the write completes without also making sure that the pages
	 * don't get reused for something else in the mean time.
	 */
#ifdef FCACHE_PAGES_PROTECTED
	struct bio_vec *bvec;
	int i;

	bio_get(bio);

	__bio_for_each_segment(bvec, bio, i, 0)
		get_page(bvec->bv_page);
#endif
}

static void fcache_put_bio_pages(struct fcache_dev *fdev, struct bio *bio)
{
#ifdef FCACHE_PAGES_PROTECTED
	struct bio_vec *bvec;
	int i;

	__bio_for_each_segment(bvec, bio, i, 0)
		put_page(bvec->bv_page);

	bio_put(bio);
#endif
}

static void fcache_chop_write_done(struct fcache_endio_data *fed)
{
	/*
	 * Last io completes.
	 */
	if (atomic_dec_and_test(&fed->completions)) {
		struct fcache_dev *fdev = fed->fdev;
		struct bio *bio = fed->bio;

		/*
		 * Release our reference to the original bio and
		 * its pages.
		 */
		fcache_put_bio_pages(fdev, bio);

		/*
		 * End the read!
		 */
		bio_endio(bio, bio->bi_size, fed->io_error);

		/*
		 * If we don't get the extent added, remember to decrement
		 * the number of extents.
		 */
		if (fcache_instantiate_extent(fdev, fed)) {
			unsigned long flags;

			spin_lock_irqsave(&fdev->lock, flags);
			fdev->nr_extents--;
			spin_unlock_irqrestore(&fdev->lock, flags);
		}

		mempool_free(fed, fed_pool);
	}
}

/*
 * Our data write to the cache completes, we can free our clone and
 * instantiate the extent block.
 */
static int fcache_extent_write_endio(struct bio *bio, unsigned int bytes,
				     int err)
{
	struct fcache_endio_data *fed;

	if (bio->bi_size)
		return 1;

	fed = bio->bi_private;

	if (!bio_flagged(bio, BIO_UPTODATE))
		fed->io_error = -EIO;

	bio_put(bio);
	fcache_chop_write_done(fed);
	return 0;
}

static void fcache_chop_read_done(struct fcache_endio_data *fed)
{
	if (atomic_dec_and_test(&fed->completions)) {
		struct bio *bio = fed->bio;

		bio_endio(bio, bio->bi_size, fed->io_error);
		mempool_free(fed, fed_pool);
	}
}

static int fcache_chop_read_endio(struct bio *bio, unsigned int bytes, int err)
{
	struct fcache_endio_data *fed;

	if (bio->bi_size)
		return 1;

	fed = bio->bi_private;

	if (!bio_flagged(bio, BIO_UPTODATE))
		fed->io_error = -EIO;

	bio_put(bio);
	fcache_chop_read_done(fed);
	return 0;
}

typedef void (chopper_done_t) (struct fcache_endio_data *);

/*
 * This is our io chopper - it hacks a bio into smaller pieces, suitable
 * for the target device. Caller supplies suitable end_io and done functions.
 */
static void fcache_io_chopper(struct fcache_dev *fdev,
			      struct fcache_endio_data *fed,
			      bio_end_io_t *endio, chopper_done_t *done, int rw)
{
	struct bio *bio = NULL;
	struct bio_vec *bv;
	unsigned int total_bytes;
	sector_t sector;
	int i, vecs;

	/*
	 * Make sure 'fed' doesn't disappear while we are still issuing
	 * ios, the artificial reference is dropped at the end.
	 */
	atomic_set(&fed->completions, 1);

	sector = fed->cache_sector;
	total_bytes = fed->fs_size;
	vecs = fed->bio->bi_vcnt;
	bio_for_each_segment(bv, fed->bio, i) {
		unsigned int len;

		if (!total_bytes)
			break;

		len = bv->bv_len;
		if (len > total_bytes)
			len = total_bytes;

		do {
			unsigned int l;

			if (!bio) {
				bio = bio_alloc(GFP_NOFS, vecs);

				bio->bi_sector = sector;
				bio->bi_bdev = fdev->bdev;
				bio->bi_end_io = endio;
				bio->bi_private = fed;
			}

			/*
			 * If successful, break out of this loop and move on.
			 */
			l = bio_add_page(bio, bv->bv_page, len, bv->bv_offset);
			if (l == len)
				break;

			BUG_ON(!bio->bi_size);

			/*
			 * We could not add this page, submit what we have
			 * and alloc a new bio.
			 */
			atomic_inc(&fed->completions);
			submit_bio(rw, bio);
			bio = NULL;
		} while (1);

		total_bytes -= len;
		sector += len >> 9;
		vecs--;
	}

	if (bio) {
		atomic_inc(&fed->completions);
		submit_bio(rw, bio);
	}

	/*
	 * Drop our reference to fed.
	 */
	done(fed);
}

/*
 * cache device has similar or higher queue restrictions than the fs
 * device - in that case, we can resubmit the bio to the device directly.
 */
static void fcache_direct_cache_write(struct fcache_dev *fdev,
				      struct fcache_endio_data *fed)
{
	struct bio *bio = bio_clone(fed->bio, GFP_NOFS);

	bio->bi_sector = fed->cache_sector;
	bio->bi_bdev = fdev->bdev;
	bio->bi_rw &= ~(1 << BIO_RW_SYNC);
	bio->bi_end_io = fcache_extent_write_endio;
	bio->bi_private = fed;

	atomic_set(&fed->completions, 1);
	submit_bio(WRITE, bio);
}

/*
 * cache device has more conservative restrictions than the fs device.
 * The safest approach is to split up the bio and let bio_add_page()
 * decide when it's time to submit the pieces.
 */
static void fcache_submit_cache_write(struct fcache_dev *fdev,
				      struct fcache_endio_data *fed)
{
	if (!fdev->chop_ios)
		fcache_direct_cache_write(fdev, fed);
	else
		fcache_io_chopper(fdev, fed, fcache_extent_write_endio,
					fcache_chop_write_done, WRITE);
}

/*
 * We punt work to fcache_work() whenever we need do work that blocks. The
 * only thing that this thread handles is submitting the extent write
 * when the real read has completed. We used to do the extent instantiation
 * here as well, but fcache_extent_write_endio handles that now.
 */
static void fcache_work(void *data)
{
	struct fcache_dev *fdev = data;

	do {
		struct fcache_endio_data *fed = NULL;
		struct bio *bio;

		spin_lock_irq(&fdev->lock);
		if (!list_empty(&fdev->list)) {
			fed = list_entry(fdev->list.next, struct fcache_endio_data,list);
			list_del_init(&fed->list);
		}
		spin_unlock_irq(&fdev->lock);

		if (!fed)
			break;

		bio = fed->bio;

		if (fed->io_error) {
			printk(KERN_ERR "fcache: read error from device\n");
			bio_endio(bio, bio->bi_size, fed->io_error);
			continue;
		}

		/*
		 * Get a ref on the original bio and pages, then
		 * we should be able to signal completion of the READ
		 * without waiting for the write to finish first.
		 */
		fcache_get_bio_pages(fdev, bio);

		/*
		 * Submit the read data as cache writes.
		 */
		fcache_submit_cache_write(fdev, fed);

		/*
		 * If fcache_get_bio_pages() could protect the pages from
		 * being changed, we could end the io here instead of in
		 * fcache_extent_fed_completes().
		 */
	} while (1);
}

/*
 * Align bio to start at extent and stop sooner if extent is short. Must
 * be called cautiously - it's only allowed to modify the bio if this is
 * a clone and a write request, reads must be fully aligned and only
 * possibly require a starting offset modification.
 */
static void fcache_bio_align(struct bio *bio, struct fcache_extent *fe)
{
	struct bio_vec *bvec;
	sector_t start, end;
	sector_t org_start, org_end;
	unsigned int org_size, org_idx;
	int i;

	start = bio->bi_sector;
	bio->bi_sector = fe->cache_sector;

	/*
	 * Nothing to do, perfectly aligned.
	 */
	if (start == fe->fs_sector && bio->bi_size == fe->fs_size)
		return;

	org_start = bio->bi_sector;
	org_end = bio->bi_sector + (bio->bi_size >> 9);
	org_size = bio->bi_size;
	org_idx = bio->bi_idx;

	/*
	 * Adjust beginning.
	 */
	if (start > fe->fs_sector)
		bio->bi_sector += (start - fe->fs_sector);
	else if (start < fe->fs_sector) {
		sector_t diff = fe->fs_sector - start;
		int idx = 0;

		BUG_ON(!(bio->bi_flags & (1 << BIO_CLONED)));
		BUG_ON(bio_data_dir(bio) != WRITE);

		/*
		 * Adjust where bio starts
		 */
		__bio_for_each_segment(bvec, bio, i, 0) {
			unsigned int bsec = bvec->bv_len >> 9;
			unsigned int this_diff = bsec;

			if (!diff)
				break;
			if (this_diff > diff)
				this_diff = diff;

			bio->bi_sector += this_diff;
			bio->bi_size -= (this_diff << 9);

			/*
			 * Bigger than this chunk, skip ahead.
			 */
			if (this_diff == bsec) {
				idx++;
				diff -= this_diff;
				continue;
			}

			/*
			 * Adjust this bvec
			 */
			bvec->bv_offset += (this_diff << 9);
			bvec->bv_len -= (this_diff << 9);
			break;
		}
		bio->bi_idx += idx;
	}

	/*
	 * Goes beyond the end, shrink size.
	 */
	end = bio->bi_sector + (bio->bi_size >> 9);
	if (end > fe->cache_sector + (fe->fs_size >> 9)) {
		sector_t diff = end - (fe->cache_sector + (fe->fs_size >> 9));
		int vecs = 0;

		BUG_ON(!(bio->bi_flags & (1 << BIO_CLONED)));
		BUG_ON(bio_data_dir(bio) != WRITE);

		/*
		 * This is __bio_for_each_segment_reverse().
		 */
		for (i = bio->bi_vcnt - 1; i >= bio->bi_idx; i--) {
			struct bio_vec *bvec = &bio->bi_io_vec[i];
			unsigned int bsec = bvec->bv_len >> 9;
			unsigned int this_diff = bsec;

			if (!diff)
				break;
			if (this_diff > diff)
				this_diff = diff;

			bio->bi_size -= (this_diff << 9);

			/*
			 * Bigger than this chunk, skip ahead.
			 */
			if (this_diff == bsec) {
				vecs++;
				diff -= this_diff;
				continue;
			}

			/*
			 * Adjust this bvec
			 */
			bvec->bv_len -= (this_diff << 9);
			break;
		}
		bio->bi_vcnt -= vecs;
	}

	BUG_ON(bio->bi_sector < fe->cache_sector);
	BUG_ON(bio->bi_sector + (bio->bi_size >> 9) > fe->cache_sector + (fe->fs_size >> 9));

	/*
	 * Invalidate the segment counts, we changed the bio layout.
	 */
	bio->bi_flags &= ~(1 << BIO_SEG_VALID);
	bio->bi_flags |= (1 << BIO_NOMERGE);
}

static int fcache_overwrite_endio(struct bio *bio, unsigned int bytes, int err)
{
	if (bio->bi_size)
		return 1;

	if (!bio_flagged(bio, BIO_UPTODATE)) {
		struct fcache_dev *fdev = bio->bi_private;

		printk(KERN_ERR "fcache: overwrite error, cache off\n");
		set_bit(FDEV_F_DOWN, &fdev->flags);
	}

	bio_put(bio);
	return 0;
}

/*
 * Schedule overwrite of some existing block(s).
 */
static int fcache_overwrite_extent(struct fcache_dev *fdev,
				   struct fcache_extent *fe, struct bio *bio)
{
	struct bio *clone = bio_clone(bio, GFP_NOFS);

	/*
	 * Just drop prefetch info on overwrites.
	 */
	if (fe->pages)
		__fcache_fe_drop(fe);

	clone->bi_bdev = fdev->bdev;
	clone->bi_end_io = fcache_overwrite_endio;
	clone->bi_private = fdev;
	fcache_bio_align(clone, fe);
	submit_bio(WRITE, clone);
	return 0;
}

/*
 * Our real data read is complete. Kick our process context handler so it
 * can submit the write to our cache.
 */
static int fcache_extent_endio(struct bio *bio, unsigned int bytes, int err)
{
	struct fcache_dev *fdev;
	struct fcache_endio_data *fed;
	unsigned long flags;

	if (bio->bi_size)
		return 1;

	fed = bio->bi_private;

	if (!bio_flagged(bio, BIO_UPTODATE))
		fed->io_error = -EIO;

	bio_put(bio);

	fdev = fed->fdev;
	spin_lock_irqsave(&fdev->lock, flags);
	list_add_tail(&fed->list, &fdev->list);
	spin_unlock_irqrestore(&fdev->lock, flags);
	queue_work(fcache_workqueue, &fdev->work);
	return 0;
}

/*
 * This initiates adding an extent to our list. We do this by cloning the
 * original bio and submitting that to the real device and when that completes
 * we write that out to the cache device and instantiate the extent.
 */
static int fcache_add_extent(struct fcache_dev *fdev, struct bio *bio)
{
	struct fcache_endio_data *fed;
	struct bio *clone;

	fed = mempool_alloc(fed_pool, GFP_NOIO);

	fed->fdev = fdev;
	fed->fs_sector = bio->bi_sector;
	fed->fs_size = bio->bi_size;
	fed->cache_sector = -1;
	fed->bio = bio;
	fed->io_error = 0;
	INIT_LIST_HEAD(&fed->list);

	/*
	 * Allocate/assign an extent block for this range
	 */
	spin_lock_irq(&fdev->lock);
	if (fdev->nr_extents < fdev->max_extents) {
		unsigned long nr = (bio->bi_size + PAGE_SIZE - 1) >> PAGE_SHIFT;

		if (fdev->next_cache_block + nr <= fdev->cache_blocks) {
			fdev->nr_extents++;
			fed->cache_sector = fdev->next_cache_block << FBLOCK_SHIFT;
			fdev->next_cache_block += nr;
		}
	}
	spin_unlock_irq(&fdev->lock);

	/*
	 * Ran out of room
	 */
	if (fed->cache_sector == -1) {
		printk(KERN_ERR "fcache: ran out of space, priming now off\n");
		fdev->priming = 0;
		mempool_free(fed, fed_pool);
		return -ENOENT;
	}

	clone = bio_clone(bio, GFP_NOFS);
	clone->bi_private = fed;
	clone->bi_end_io = fcache_extent_endio;
	clone->bi_rw |= (1 << BIO_RW_SYNC);

	generic_make_request(clone);
	return 0;
}

static int fcache_parse_extents(struct fcache_dev *fdev, void *addr,
				unsigned int max_extents)
{
	int nr_extents = PAGE_SIZE / sizeof(struct fcache_ondisk_extent);
	int extents_read;

	if (nr_extents > max_extents)
		nr_extents = max_extents;

	extents_read = 0;
	while (nr_extents) {
		struct fcache_ondisk_extent *foe = addr;
		struct fcache_extent *fe;

		fe = fcache_get_fe(GFP_KERNEL);
		if (unlikely(!fe))
			return -ENOMEM;

		fe->fs_sector = be64_to_cpu(foe->fs_sector);
		fe->cache_sector = be64_to_cpu(foe->cache_sector);
		fe->fs_size = be32_to_cpu(foe->fs_size);

		spin_lock_irq(&fdev->lock);
		if (fcache_tree_link(fdev, fe))
			BUG();
		fcache_fe_link(fdev, fe);
		spin_unlock_irq(&fdev->lock);

		nr_extents--;
		extents_read++;
		addr += sizeof(*foe);
	}

	return extents_read;
}

static int fcache_read_extents(struct fcache_dev *fdev)
{
	unsigned int nr_extents = fdev->nr_extents;
	int ret, extents, total_extents;
	struct page *page;
	sector_t index;
	void *p;

	page = alloc_page(GFP_KERNEL);
	if (unlikely(!page))
		return -ENOMEM;

	ret = 0;
	total_extents = 0;
	index = FCACHE_EXTENT_BLOCK;
	while (nr_extents) {
		ret = fcache_rw_page(fdev, index, page, READ);
		if (ret)
			break;

		p = page_address(page);
		extents = fcache_parse_extents(fdev, p, nr_extents);

		if (extents < 0) {
			ret = extents;
			break;
		}

		index++;
		nr_extents -= extents;
		total_extents += extents;
	}

	__free_page(page);

	if (ret)
		return ret;

	return total_extents;
}

/*
 * Read an existing fcache header from the device, and then proceed to
 * reading and adding the extents to out prio tree.
 */
static int fcache_load_header(struct fcache_dev *fdev, int serial)
{
	struct fcache_header *header = NULL;
	struct page *page;
	int ret, wrong_serial = 0;
	char b[BDEVNAME_SIZE];

	page = alloc_page(GFP_HIGHUSER);
	if (unlikely(!page))
		return -ENOMEM;

	ret = fcache_rw_page(fdev, FCACHE_HEADER_BLOCK, page, READ);
	if (unlikely(ret))
		goto err;

	ret = -EINVAL;
	header = kmap_atomic(page, KM_USER0);
	if (header->magic != FCACHE_MAGIC) {
		printk(KERN_ERR "fcache: bad magic %x\n", header->magic);
		goto err;
	}
	if (header->version != FCACHE_VERSION) {
		printk(KERN_ERR "fcache: bad version %d\n", header->version);
		goto err;
	}
	if (strcmp(bdevname(fdev->fs_bdev, b), header->fs_dev)) {
		printk(KERN_ERR "fcache: device mismatch (%s/%s\n", b,
							header->fs_dev);
		goto err;
	}
	if (header->fs_start_sector != fdev->fs_start_sector ||
	    header->fs_sectors != fdev->fs_sectors) {
		printk(KERN_ERR "fcache: fs appears to have changed size\n");
		goto err;
	}

	fdev->nr_extents = header->nr_extents;
	fdev->max_extents = header->max_extents;

	/*
	 * Don't fail on out-of-date serial, just warn that the user needs
	 * to prime the cache again. Until then we'll just bypass the cache.
	 */
	if (header->serial != serial) {
		printk(KERN_ERR "fcache: found serial %d, expected %d.\n",
							header->serial, serial);
		printk(KERN_ERR "fcache: reprime the cache!\n");
		wrong_serial = 1;
	}

	fdev->serial = header->serial;
	kunmap_atomic(header, KM_USER0);
	__free_page(page);

	if (!wrong_serial) {
		printk("fcache: header looks valid (extents=%ld, serial=%u)\n",
						fdev->nr_extents, fdev->serial);

		ret = fcache_read_extents(fdev);
		printk("fcache: loaded %d extents\n", ret);

		/*
		 * If we don't find all the extents we require, fail.
		 */
		if (ret != fdev->nr_extents) {
			fcache_free_links(fdev);
			ret = -EINVAL;
		} else
			ret = 0;
	}

	return ret;
err:
	__free_page(page);
	if (header)
		kunmap_atomic(header, KM_USER0);
	return ret;
}

/*
 * We use this range to decide when to log an io to the target device.
 */
static void fcache_fill_fs_size(struct fcache_dev *fdev)
{
	struct block_device *bdev = fdev->fs_bdev;

	/*
	 * Partition or whole device?
	 */
	if (bdev != bdev->bd_contains) {
		struct hd_struct *p = bdev->bd_part;

		fdev->fs_start_sector = p->start_sect;
		fdev->fs_sectors = p->nr_sects;
	} else {
		fdev->fs_start_sector = 0;
		fdev->fs_sectors = bdev->bd_inode->i_size >> 9;
	}
}

static void fcache_fill_cache_size(struct fcache_dev *fdev)
{
	struct block_device *bdev = fdev->bdev;

	/*
	 * Partition or whole device?
	 */
	if (bdev != bdev->bd_contains) {
		struct hd_struct *p = bdev->bd_part;

		fdev->cache_start_sector = p->start_sect;
		fdev->cache_blocks = p->nr_sects >> FBLOCK_SHIFT;
	} else {
		fdev->cache_start_sector = 0;
		fdev->cache_blocks = bdev->bd_inode->i_size >> PAGE_SHIFT;
	}
}

static int fcache_prefetch_endio(struct bio *bio, unsigned int bytes, int err)
{
	struct bio_vec *bvec;
	int i;

	if (bio->bi_size)
		return 1;

	__bio_for_each_segment(bvec, bio, i, 0) {
		if (!bio_flagged(bio, BIO_UPTODATE))
			ClearPageUptodate(bvec->bv_page);

		unlock_page(bvec->bv_page);
	}

	bio_put(bio);
	return 0;
}

/*
 * Prefetch from this fe and forward for at least 128kb. It may be more,
 * we always prefetch full extents. We do not prefetch extents that are
 * bigger than 32kb as that should go at full speed anyways.
 */
static void fcache_do_prefetch(struct fcache_dev *fdev,
			       struct fcache_extent *fe)
{
	struct page **map;
	struct fcache_extent *fenxt;
	unsigned int pages, i, ret, bytes, this_pages;
	struct bio *bio;
	sector_t sec;

	if (pcache_disable)
		return;
	if (fe->fs_size >= 64 * 1024)
		return;
	if (fe->pages)
		return;

	sec = fe->cache_sector;
	bytes = 0;
	this_pages = 0;
	bio = NULL;
	while (bytes < 128*1024) {
		pages = (fe->fs_size + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
		map = kmalloc(pages * sizeof(struct page *), GFP_NOIO);
		fe->pages = map;
		fe->numpages = pages;

		for (i = 0; i < pages; i++) {
			map[i] = alloc_page(GFP_NOIO);
			SetPageUptodate(map[i]);
			SetPageLocked(map[i]);
		}

		for (i = 0; i < pages; i++) {
			if (!bio) {
get_bio:
				bio = bio_alloc(GFP_NOIO, BIO_MAX_PAGES);

				bio->bi_sector = sec;
				bio->bi_bdev = fdev->bdev;
				bio->bi_end_io = fcache_prefetch_endio;
				this_pages = 0;
			}

			ret = bio_add_page(bio, map[i], PAGE_CACHE_SIZE, 0);
			if (ret != PAGE_CACHE_SIZE) {
				submit_bio(READ, bio);
				bio = NULL;
				goto get_bio;
			}
			this_pages++;
			bytes += PAGE_CACHE_SIZE;
			sec += FBLOCK_SIZE;
		}

		if (fe->fe_list.next == &fdev->fe_list)
			break;

		fenxt = list_entry(fe->fe_list.next, struct fcache_extent, fe_list);
		if (fenxt->pages)
			break;
		if (fe->cache_sector + (fe->fs_size >> 9) != fenxt->cache_sector)
			break;
		fe = fenxt;
	}

	if (bio)
		submit_bio(READ, bio);

	fdev->pcache_kb += bytes >> 10;
}

static void __fcache_fe_drop(struct fcache_extent *fe)
{
	struct page **pages = xchg(&fe->pages, NULL);

	if (pages) {
		int i;

		for (i = 0; i < fe->numpages; i++)
			__free_page(pages[i]);

		fe->numpages = fe->readpages = 0;
		kfree(pages);
	}
}

/*
 * Assume that we can drop the prefetch data, if we have as many reads
 * as pages. Wont be true for multiple reads of the data, however the page
 * cache should prevent that.
 */
static void fcache_fe_checkdrop(struct fcache_extent *fe)
{
	if (fe->readpages >= fe->numpages)
		__fcache_fe_drop(fe);
}

static int fcache_read_fe_cached(struct fcache_dev *fdev,
				 struct fcache_extent *fe, struct bio *bio)
{
	unsigned long pgoff, boff;
	struct bio_vec *bvec;
	char *src, *dst;
	int i;

	if (pcache_disable)
		return 1;

	/*
	 * page index offset
	 */
	pgoff = ((bio->bi_sector - fe->fs_sector) << 9) / PAGE_CACHE_SIZE;
	boff = ((bio->bi_sector - fe->fs_sector) << 9) & (PAGE_CACHE_SIZE - 1);

	/*
	 * Loop over bio, copying data.
	 */
	bio_for_each_segment(bvec, bio, i) {
		if (pgoff == fe->numpages) {
			fcache_fe_checkdrop(fe);
			BUG_ON(fe->fe_list.next == &fdev->fe_list);
			fe = list_entry(fe->fe_list.next, struct fcache_extent, fe_list);
			pgoff = 0;
		}

		wait_on_page_locked(fe->pages[pgoff]);

		/*
		 * IO error, bail.
		 */
		if (unlikely(!PageUptodate(fe->pages[pgoff]))) {
			__fcache_fe_drop(fe);
			return 1;
		}

		WARN_ON(boff + bvec->bv_len > PAGE_CACHE_SIZE);

		src = kmap_atomic(fe->pages[pgoff], KM_USER0);
		dst = kmap_atomic(bvec->bv_page, KM_USER1);

		memcpy(dst + bvec->bv_offset, src + boff, bvec->bv_len);

		kunmap_atomic(src, KM_USER0);
		kunmap_atomic(dst, KM_USER1);

		pgoff++;
		boff = 0;
		fe->readpages++;
	}

	fcache_fe_checkdrop(fe);
	return 0;
}

static int fcache_read_fe(struct fcache_dev *fdev, struct fcache_extent *fe,
			  struct bio *bio)
{
	fdev->hits++;

	fcache_do_prefetch(fdev, fe);

	/*
	 * If we have the data already (it was prefetched), just copy it
	 * over and end it.
	 */
	if (fe->pages && !fcache_read_fe_cached(fdev, fe, bio)) {
		fdev->pcache_hits++;
		bio_endio(bio, bio->bi_size, 0);
		return 0;
	}

	/*
	 * We need to issue IO to our cache, align and submit appropriately.
	 */
	fcache_bio_align(bio, fe);

	/*
	 * If we don't have to chop it up, just let generic_make_request()
	 * handle the stacking. Otherwise, return handled and pass to chopper.
	 */
	if (fdev->chop_ios) {
		struct fcache_endio_data *fed;

		fed = mempool_alloc(fed_pool, GFP_NOIO);

		fed->fdev = fdev;
		fed->cache_sector = bio->bi_sector;
		fed->fs_size = bio->bi_size;
		fed->bio = bio;
		fed->io_error = 0;
		fcache_io_chopper(fdev, fed, fcache_chop_read_endio,
					fcache_chop_read_done, READ);
		return 0;
	}

	bio->bi_bdev = fdev->bdev;
	return 1;
}

/*
 * This is a read request, check if we have that block. If we do, then
 * just redirect. If not, pass it through.
 */
static int fcache_read_request(struct fcache_dev *fdev, request_queue_t *q,
			       struct bio *bio)
{
	struct fcache_extent *extents[MAX_FE];
	struct fcache_extent *fe;
	sector_t end_sector;
	int i, nr;

	end_sector = bio->bi_sector + (bio->bi_size >> 9) - 1;
	nr = fcache_lookup_extent(fdev, bio->bi_sector, end_sector, extents);
	if (!nr) {
		/*
		 * Not there, redirect to original but schedule adding this
		 * extent to our list if we are priming.
		 */
		if (fdev->priming && !fcache_add_extent(fdev, bio))
			return 0;

		fdev->misses++;
		return fdev->mfn(q, bio);
	}

	if (nr == MAX_FE)
		printk("FOUND MAX\n");

	/*
	 * If range is at least as big, we use our cache. If not, cop out
	 * and just submit to real device.
	 */
	for (i = 0; i < nr; i++) {
		sector_t end_fe, end_bi;
		fe = extents[i];

		end_fe = fe->fs_sector + (fe->fs_size >> 9);
		end_bi = bio->bi_sector + (bio->bi_size >> 9);

		/*
		 * match!
		 */
		if (bio->bi_sector >= fe->fs_sector && end_bi <= end_fe)
			break;

		fe = NULL;
	}

	/*
	 * Nopes, send to real device.
	 */
	if (!fe) {
		fdev->partial++;
		fdev->misses++;
		return fdev->mfn(q, bio);
	}

	return fcache_read_fe(fdev, fe, bio);
}

/*
 * If we are priming the cache, always add this block. If not, then we still
 * need to overwrite this block if it's in our cache.
 */
static int fcache_write_request(struct fcache_dev *fdev, request_queue_t *q,
				struct bio *bio)
{
	struct fcache_extent *extents[MAX_FE];
	struct fcache_extent *fe;
	sector_t start = bio->bi_sector;
	sector_t end = start + (bio->bi_size >> 9) - 1;
	int i, nr;

repeat:
	nr = fcache_lookup_extent(fdev, start, end, extents);

	/*
	 * Find out what to overwrite, if anything.
	 */
	for (i = 0; i < nr; i++) {
		fe = extents[i];

		if (fe->ow_time == -1UL)
			fe->ow_time = jiffies + FCACHE_OVERWRITE_TIME;

		if (!fdev->priming && time_before(jiffies, fe->ow_time) &&
		    ++fe->overwrites >= FCACHE_MAX_OVERWRITES) {
			fdev->extent_drops++;
			fe->valid = 0;
		} else {
			/*
			 * TODO: possibly split extent in two (or chop off
			 * a part of the end/front) instead of always
			 * overwriting.
			 */
			fdev->overwrites++;
			fcache_overwrite_extent(fdev, fe, bio);
		}
	}

	/*
	 * If i == MAX_FE, there _may_ be more extents. Repeat lookup, start
	 * from the end of last request.
	 */
	if (i == MAX_FE) {
		fe = extents[i - 1];
		start = fe->fs_sector + (fe->fs_size >> 9);
		if (start < end)
			goto repeat;
	}

	return fdev->mfn(q, bio);
}

/*
 * This is the only case where we resubmit an io to the device but don't
 * want to count it as part of io we log.
 */
#define fcache_bio_seen(bio)	((bio)->bi_end_io == fcache_extent_endio)

static int fcache_make_request(request_queue_t *q, struct bio *bio)
{
	struct fcache_dev *fdev = &fcache_dev;

	/*
	 * If it's in the sector range we are monitoring and the device isn't
	 * being shutdown, then pass it on. Assume a bio doesn't span into
	 * the next partition, so don't bother accounting for size.
	 */
	if ((bio->bi_sector >= fdev->fs_start_sector) &&
	    (bio->bi_sector < (fdev->fs_start_sector + fdev->fs_sectors)) &&
	    !test_bit(FDEV_F_DOWN, &fdev->flags) &&
	    !fcache_bio_seen(bio)) {

		fdev->ios[bio_data_dir(bio)]++;

		if (bio_data_dir(bio) == READ)
			return fcache_read_request(fdev, q, bio);

		return fcache_write_request(fdev, q, bio);
	}

	/*
	 * Pass through to original make_request_fn.
	 */
	return fdev->mfn(q, bio);
}

/*
 * Attach the cache device 'bdev' to 'fdev'.
 */
static int fcache_setup_dev(struct fcache_dev *fdev,
			    struct block_device *fs_bdev,
			    struct block_device *bdev,
			    int priming, int serial)
{
	request_queue_t *fs_q, *cache_q;
	char b[BDEVNAME_SIZE];
	int ret;

	memset(fdev, 0, sizeof(*fdev));
	INIT_PRIO_TREE_ROOT(&fdev->prio_root);
	spin_lock_init(&fdev->lock);
	INIT_LIST_HEAD(&fdev->list);
	INIT_LIST_HEAD(&fdev->fe_list);
	INIT_WORK(&fdev->work, fcache_work, fdev);
	fdev->priming = priming;
	fdev->fs_bdev = fs_bdev;
	fdev->bdev = bdev;

	ret = -EINVAL;

	fs_q = bdev_get_queue(fs_bdev);
	cache_q = bdev_get_queue(bdev);
	if (!fs_q || !cache_q)
		goto out;

	/*
	 * Chop up outgoing ios, if the target is a different queue. We could
	 * look closer at limits, but it's fragile and pretty pointless.
	 */
	if (fs_q != cache_q)
		fdev->chop_ios = 1;

	/*
	 * Some other device already monitoring this block_device?
	 */
	ret = -EBUSY;
	if (fs_q->make_request_fn == fcache_make_request)
		goto out;

	ret = bd_claim(bdev, fcache_setup_dev);
	if (ret < 0)
		goto out;

	ret = block_size(bdev);
	if (ret != PAGE_SIZE) {
		fdev->old_bs = ret;
		ret = set_blocksize(bdev, PAGE_SIZE);
		if (ret < 0)
			goto out_release;
	} else
		ret = 0;

	fcache_fill_cache_size(fdev);
	fcache_fill_fs_size(fdev);

	if (priming) {
		fdev->serial = serial;
		ret = fcache_write_new_header(fdev);
	} else
		ret = fcache_load_header(fdev, serial);

	if (!ret) {
		printk("fcache: %s opened successfully (%spriming)\n",
						bdevname(bdev, b),
						priming ? "" : "not ");
		return 0;
	}

out_release:
	bd_release(fdev->bdev);
out:
	blkdev_put(fdev->bdev);
	fdev->bdev = NULL;
	return ret;
}

/*
 * Return fdev->bdev to its original state.
 */
static void fcache_shutdown_dev(struct fcache_dev *fdev,
				struct block_device *bdev)
{
	if (fdev->bdev) {
		if (fdev->mfn) {
			request_queue_t *q = bdev_get_queue(bdev);

			(void) xchg(&q->make_request_fn, fdev->mfn);
		}
		sync_blockdev(fdev->bdev);
		if (fdev->old_bs)
			set_blocksize(fdev->bdev, fdev->old_bs);

		bd_release(fdev->bdev);
		blkdev_put(fdev->bdev);
		fdev->bdev = NULL;
		INIT_PRIO_TREE_ROOT(&fdev->prio_root);
	}
}

/*
 * bdev is the file system device, cache_dev is the device we want to store
 * the cache on.
 */
int fcache_dev_open(struct block_device *bdev, unsigned long cache_dev,
		    int priming, int serial)
{
	struct block_device *fcache_bdev;
	request_queue_t *q;
	int ret;

	if (disable)
		return 0;
	if (fcache_dev.bdev)
		return -EBUSY;

	fcache_bdev = open_by_devnum(cache_dev, FMODE_READ|FMODE_WRITE);
	if (IS_ERR(fcache_bdev))
		return PTR_ERR(fcache_bdev);

	ret = fcache_setup_dev(&fcache_dev, bdev, fcache_bdev, priming, serial);
	if (ret)
		return ret;

	q = bdev_get_queue(bdev);
	fcache_dev.mfn = xchg(&q->make_request_fn, fcache_make_request);
	return 0;
}

EXPORT_SYMBOL(fcache_dev_open);

void fcache_dev_close(struct block_device *bdev, int serial)
{
	struct fcache_dev *fdev = &fcache_dev;

	if (disable)
		return;

	if (!fdev->bdev)
		return;

	printk("fcache: ios r/w %u/%u, hits %u, misses %u, overwrites %u, "
					"extent_merges=%d, extent_drops=%d "
					"pcache_kb=%lu, pcache_hits=%d, "
					"partial=%u\n",
					fdev->ios[0], fdev->ios[1], fdev->hits,
					fdev->misses, fdev->overwrites,
					fdev->extent_merges,
					fdev->extent_drops,
					fdev->pcache_kb, fdev->pcache_hits,
					fdev->partial);

	fdev->serial = serial;

	sync_blockdev(bdev);
	set_bit(FDEV_F_DOWN, &fdev->flags);

	if (fdev->priming)
		fcache_write_extents(fdev);

	fcache_write_header(fdev);
	fcache_free_links(fdev);
	fcache_shutdown_dev(fdev, bdev);
}

EXPORT_SYMBOL(fcache_dev_close);

static int fcache_init(void)
{
	fcache_slab = kmem_cache_create("fcache", sizeof(struct fcache_extent),
					0, 0, NULL, NULL);
	if (!fcache_slab)
		return -ENOMEM;

	fcache_fed_slab = kmem_cache_create("fcache_fed",
					sizeof(struct fcache_endio_data), 0, 0,
					NULL, NULL);
	if (!fcache_fed_slab) {
		kmem_cache_destroy(fcache_slab);
		return -ENOMEM;
	}

	fed_pool = mempool_create_slab_pool(1, fcache_fed_slab);
	if (!fed_pool) {
		kmem_cache_destroy(fcache_slab);
		kmem_cache_destroy(fcache_fed_slab);
		return -ENOMEM;
	}

	fcache_workqueue = create_singlethread_workqueue("fcached");
	if (!fcache_workqueue)
		panic("fcache: failed to create fcached\n");

	return 0;
}

static void fcache_exit(void)
{
	destroy_workqueue(fcache_workqueue);
	kmem_cache_destroy(fcache_slab);
	kmem_cache_destroy(fcache_fed_slab);
	mempool_destroy(fed_pool);
}

MODULE_AUTHOR("Jens Axboe <axboe@suse.de>");
MODULE_LICENSE("GPL");

module_init(fcache_init);
module_exit(fcache_exit);
