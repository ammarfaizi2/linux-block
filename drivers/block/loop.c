/*
 *  linux/drivers/block/loop.c
 *
 *  Written by Theodore Ts'o, 3/29/93
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 *
 * DES encryption plus some minor changes by Werner Almesberger, 30-MAY-1993
 * more DES encryption plus IDEA encryption by Nicholas J. Leon, June 20, 1996
 *
 * Modularized and updated for 1.1.16 kernel - Mitch Dsouza 28th May 1994
 * Adapted for 1.3.59 kernel - Andries Brouwer, 1 Feb 1996
 *
 * Fixed do_loop_request() re-entrancy - Vincent.Renardias@waw.com Mar 20, 1997
 *
 * Added devfs support - Richard Gooch <rgooch@atnf.csiro.au> 16-Jan-1998
 *
 * Handle sparse backing files correctly - Kenn Humborg, Jun 28, 1998
 *
 * Loadable modules and other fixes by AK, 1998
 *
 * Make real block number available to downstream transfer functions, enables
 * CBC (and relatives) mode encryption requiring unique IVs per data block.
 * Reed H. Petty, rhp@draper.net
 *
 * Maximum number of loop devices now dynamic via max_loop module parameter.
 * Russell Kroll <rkroll@exploits.org> 19990701
 *
 * Maximum number of loop devices when compiled-in now selectable by passing
 * max_loop=<1-255> to the kernel on boot.
 * Erik I. Bolsø, <eriki@himolde.no>, Oct 31, 1999
 *
 * Completely rewrite request handling to be make_request_fn style and
 * non blocking, pushing work to a helper thread. Lots of fixes from
 * Al Viro too.
 * Jens Axboe <axboe@suse.de>, Nov 2000
 *
 * Support up to 256 loop devices
 * Heinz Mauelshagen <mge@sistina.com>, Feb 2002
 *
 * Support for falling back on the write file operation when the address space
 * operations write_begin is not available on the backing filesystem.
 * Anton Altaparmakov, 16 Feb 2005
 *
 * Still To Fix:
 * - Advisory locking is ignored here.
 * - Should use an own CAP_* category instead of CAP_SYS_ADMIN
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/loop.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>		/* for invalidate_bdev() */
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/kthread.h>
#include <linux/splice.h>
#include <linux/extent_map.h>

#include <asm/uaccess.h>

static LIST_HEAD(loop_devices);
static DEFINE_MUTEX(loop_devices_mutex);

static int max_part;
static int part_shift;

/*
 * Transfer functions
 */
static int transfer_none(struct loop_device *lo, int cmd,
			 struct page *raw_page, unsigned raw_off,
			 struct page *loop_page, unsigned loop_off,
			 int size, sector_t real_block)
{
	char *raw_buf = kmap_atomic(raw_page, KM_USER0) + raw_off;
	char *loop_buf = kmap_atomic(loop_page, KM_USER1) + loop_off;

	if (cmd == READ)
		memcpy(loop_buf, raw_buf, size);
	else
		memcpy(raw_buf, loop_buf, size);

	kunmap_atomic(raw_buf, KM_USER0);
	kunmap_atomic(loop_buf, KM_USER1);
	cond_resched();
	return 0;
}

static int transfer_xor(struct loop_device *lo, int cmd,
			struct page *raw_page, unsigned raw_off,
			struct page *loop_page, unsigned loop_off,
			int size, sector_t real_block)
{
	char *raw_buf = kmap_atomic(raw_page, KM_USER0) + raw_off;
	char *loop_buf = kmap_atomic(loop_page, KM_USER1) + loop_off;
	char *in, *out, *key;
	int i, keysize;

	if (cmd == READ) {
		in = raw_buf;
		out = loop_buf;
	} else {
		in = loop_buf;
		out = raw_buf;
	}

	key = lo->lo_encrypt_key;
	keysize = lo->lo_encrypt_key_size;
	for (i = 0; i < size; i++)
		*out++ = *in++ ^ key[(i & 511) % keysize];

	kunmap_atomic(raw_buf, KM_USER0);
	kunmap_atomic(loop_buf, KM_USER1);
	cond_resched();
	return 0;
}

static int xor_init(struct loop_device *lo, const struct loop_info64 *info)
{
	if (unlikely(info->lo_encrypt_key_size <= 0))
		return -EINVAL;
	return 0;
}

static struct loop_func_table none_funcs = {
	.number = LO_CRYPT_NONE,
	.transfer = transfer_none,
}; 	

static struct loop_func_table xor_funcs = {
	.number = LO_CRYPT_XOR,
	.transfer = transfer_xor,
	.init = xor_init
}; 	

/* xfer_funcs[0] is special - its release function is never called */
static struct loop_func_table *xfer_funcs[MAX_LO_CRYPT] = {
	&none_funcs,
	&xor_funcs
};

static loff_t get_loop_size(struct loop_device *lo, struct file *file)
{
	loff_t size, offset, loopsize;

	/* Compute loopsize in bytes */
	size = i_size_read(file->f_mapping->host);
	offset = lo->lo_offset;
	loopsize = size - offset;
	if (lo->lo_sizelimit > 0 && lo->lo_sizelimit < loopsize)
		loopsize = lo->lo_sizelimit;

	/*
	 * Unfortunately, if we want to do I/O on the device,
	 * the number of 512-byte sectors has to fit into a sector_t.
	 */
	return loopsize >> 9;
}

static int
figure_loop_size(struct loop_device *lo)
{
	loff_t size = get_loop_size(lo, lo->lo_backing_file);
	sector_t x = (sector_t)size;

	if (unlikely((loff_t)x != size))
		return -EFBIG;

	set_capacity(lo->lo_disk, x);
	return 0;					
}

static inline int
lo_do_transfer(struct loop_device *lo, int cmd,
	       struct page *rpage, unsigned roffs,
	       struct page *lpage, unsigned loffs,
	       int size, sector_t rblock)
{
	if (unlikely(!lo->transfer))
		return 0;

	return lo->transfer(lo, cmd, rpage, roffs, lpage, loffs, size, rblock);
}

/**
 * do_lo_send_aops - helper for writing data to a loop device
 *
 * This is the fast version for backing filesystems which implement the address
 * space operations write_begin and write_end.
 */
static int do_lo_send_aops(struct loop_device *lo, struct bio_vec *bvec,
		loff_t pos, struct page *unused)
{
	struct file *file = lo->lo_backing_file; /* kudos to NFsckingS */
	struct address_space *mapping = file->f_mapping;
	pgoff_t index;
	unsigned offset, bv_offs;
	int len, ret;

	mutex_lock(&mapping->host->i_mutex);
	index = pos >> PAGE_CACHE_SHIFT;
	offset = pos & ((pgoff_t)PAGE_CACHE_SIZE - 1);
	bv_offs = bvec->bv_offset;
	len = bvec->bv_len;
	while (len > 0) {
		sector_t IV;
		unsigned size, copied;
		int transfer_result;
		struct page *page;
		void *fsdata;

		IV = ((sector_t)index << (PAGE_CACHE_SHIFT - 9))+(offset >> 9);
		size = PAGE_CACHE_SIZE - offset;
		if (size > len)
			size = len;

		ret = pagecache_write_begin(file, mapping, pos, size, 0,
							&page, &fsdata);
		if (ret)
			goto fail;

		transfer_result = lo_do_transfer(lo, WRITE, page, offset,
				bvec->bv_page, bv_offs, size, IV);
		copied = size;
		if (unlikely(transfer_result))
			copied = 0;

		ret = pagecache_write_end(file, mapping, pos, size, copied,
							page, fsdata);
		if (ret < 0 || ret != copied)
			goto fail;

		if (unlikely(transfer_result))
			goto fail;

		bv_offs += copied;
		len -= copied;
		offset = 0;
		index++;
		pos += copied;
	}
	ret = 0;
out:
	mutex_unlock(&mapping->host->i_mutex);
	return ret;
fail:
	ret = -1;
	goto out;
}

/**
 * __do_lo_send_write - helper for writing data to a loop device
 *
 * This helper just factors out common code between do_lo_send_direct_write()
 * and do_lo_send_write().
 */
static int __do_lo_send_write(struct file *file,
		u8 *buf, const int len, loff_t pos)
{
	ssize_t bw;
	mm_segment_t old_fs = get_fs();

	set_fs(get_ds());
	bw = file->f_op->write(file, buf, len, &pos);
	set_fs(old_fs);
	if (likely(bw == len))
		return 0;
	printk(KERN_ERR "loop: Write error at byte offset %llu, length %i.\n",
			(unsigned long long)pos, len);
	if (bw >= 0)
		bw = -EIO;
	return bw;
}

/**
 * do_lo_send_direct_write - helper for writing data to a loop device
 *
 * This is the fast, non-transforming version for backing filesystems which do
 * not implement the address space operations write_begin and write_end.
 * It uses the write file operation which should be present on all writeable
 * filesystems.
 */
static int do_lo_send_direct_write(struct loop_device *lo,
		struct bio_vec *bvec, loff_t pos, struct page *page)
{
	ssize_t bw = __do_lo_send_write(lo->lo_backing_file,
			kmap(bvec->bv_page) + bvec->bv_offset,
			bvec->bv_len, pos);
	kunmap(bvec->bv_page);
	cond_resched();
	return bw;
}

/**
 * do_lo_send_write - helper for writing data to a loop device
 *
 * This is the slow, transforming version for filesystems which do not
 * implement the address space operations write_begin and write_end.  It
 * uses the write file operation which should be present on all writeable
 * filesystems.
 *
 * Using fops->write is slower than using aops->{prepare,commit}_write in the
 * transforming case because we need to double buffer the data as we cannot do
 * the transformations in place as we do not have direct access to the
 * destination pages of the backing file.
 */
static int do_lo_send_write(struct loop_device *lo, struct bio_vec *bvec,
		loff_t pos, struct page *page)
{
	int ret = lo_do_transfer(lo, WRITE, page, 0, bvec->bv_page,
			bvec->bv_offset, bvec->bv_len, pos >> 9);
	if (likely(!ret))
		return __do_lo_send_write(lo->lo_backing_file,
				page_address(page), bvec->bv_len,
				pos);
	printk(KERN_ERR "loop: Transfer error at byte offset %llu, "
			"length %i.\n", (unsigned long long)pos, bvec->bv_len);
	if (ret > 0)
		ret = -EIO;
	return ret;
}

static int lo_send(struct loop_device *lo, struct bio *bio, loff_t pos)
{
	int (*do_lo_send)(struct loop_device *, struct bio_vec *, loff_t,
			struct page *page);
	struct bio_vec *bvec;
	struct page *page = NULL;
	int i, ret = 0;

	do_lo_send = do_lo_send_aops;
	if (!(lo->lo_flags & LO_FLAGS_USE_AOPS)) {
		do_lo_send = do_lo_send_direct_write;
		if (lo->transfer != transfer_none) {
			page = alloc_page(GFP_NOIO | __GFP_HIGHMEM);
			if (unlikely(!page))
				goto fail;
			kmap(page);
			do_lo_send = do_lo_send_write;
		}
	}
	bio_for_each_segment(bvec, bio, i) {
		ret = do_lo_send(lo, bvec, pos, page);
		if (ret < 0)
			break;
		pos += bvec->bv_len;
	}
	if (page) {
		kunmap(page);
		__free_page(page);
	}
out:
	return ret;
fail:
	printk(KERN_ERR "loop: Failed to allocate temporary page for write.\n");
	ret = -ENOMEM;
	goto out;
}

struct lo_read_data {
	struct loop_device *lo;
	struct page *page;
	unsigned offset;
	int bsize;
};

static int
lo_splice_actor(struct pipe_inode_info *pipe, struct pipe_buffer *buf,
		struct splice_desc *sd)
{
	struct lo_read_data *p = sd->u.data;
	struct loop_device *lo = p->lo;
	struct page *page = buf->page;
	sector_t IV;
	size_t size;
	int ret;

	ret = buf->ops->confirm(pipe, buf);
	if (unlikely(ret))
		return ret;

	IV = ((sector_t) page->index << (PAGE_CACHE_SHIFT - 9)) +
							(buf->offset >> 9);
	size = sd->len;
	if (size > p->bsize)
		size = p->bsize;

	if (lo_do_transfer(lo, READ, page, buf->offset, p->page, p->offset, size, IV)) {
		printk(KERN_ERR "loop: transfer error block %ld\n",
		       page->index);
		size = -EINVAL;
	}

	flush_dcache_page(p->page);

	if (size > 0)
		p->offset += size;

	return size;
}

static int
lo_direct_splice_actor(struct pipe_inode_info *pipe, struct splice_desc *sd)
{
	return __splice_from_pipe(pipe, sd, lo_splice_actor);
}

static int
do_lo_receive(struct loop_device *lo,
	      struct bio_vec *bvec, int bsize, loff_t pos)
{
	struct lo_read_data cookie;
	struct splice_desc sd;
	struct file *file;
	long retval;

	cookie.lo = lo;
	cookie.page = bvec->bv_page;
	cookie.offset = bvec->bv_offset;
	cookie.bsize = bsize;

	sd.len = 0;
	sd.total_len = bvec->bv_len;
	sd.flags = 0;
	sd.pos = pos;
	sd.u.data = &cookie;

	file = lo->lo_backing_file;
	retval = splice_direct_to_actor(file, &sd, lo_direct_splice_actor);

	if (retval < 0)
		return retval;

	return 0;
}

static int
lo_receive(struct loop_device *lo, struct bio *bio, int bsize, loff_t pos)
{
	struct bio_vec *bvec;
	int i, ret = 0;

	bio_for_each_segment(bvec, bio, i) {
		ret = do_lo_receive(lo, bvec, bsize, pos);
		if (ret < 0)
			break;
		pos += bvec->bv_len;
	}
	return ret;
}

static int do_bio_filebacked(struct loop_device *lo, struct bio *bio)
{
	loff_t pos;
	int ret;

	pos = ((loff_t) bio->bi_sector << 9) + lo->lo_offset;
	if (bio_rw(bio) == WRITE)
		ret = lo_send(lo, bio, pos);
	else
		ret = lo_receive(lo, bio, lo->lo_blocksize, pos);
	return ret;
}

#define __lo_throttle(wq, lock, condition)				\
do {									\
	DEFINE_WAIT(__wait);						\
	for (;;) {							\
		prepare_to_wait((wq), &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		spin_unlock_irq((lock));				\
		wake_up(&lo->lo_event);					\
		io_schedule();						\
		spin_lock_irq((lock));					\
	}								\
	finish_wait((wq), &__wait);					\
} while (0)								\

#define LO_BIO_THROTTLE		128
#define LO_BIO_THROTTLE_LOW	(LO_BIO_THROTTLE / 2)

/*
 * A normal block device will throttle on request allocation. Do the same
 * for loop to prevent millions of bio's queued internally.
 */
static void loop_bio_throttle(struct loop_device *lo, struct bio *bio)
{
	__lo_throttle(&lo->lo_bio_wait, &lo->lo_lock,
				lo->lo_bio_cnt < LO_BIO_THROTTLE);
}

static void loop_bio_timer(unsigned long data)
{
	struct loop_device *lo = (struct loop_device *) data;

	wake_up(&lo->lo_event);
}

/*
 * Add bio to back of pending list and wakeup thread
 */
static void loop_add_bio(struct loop_device *lo, struct bio *bio)
{
	loop_bio_throttle(lo, bio);

	if (lo->lo_biotail) {
		lo->lo_biotail->bi_next = bio;
		lo->lo_biotail = bio;
	} else
		lo->lo_bio = lo->lo_biotail = bio;

	lo->lo_bio_cnt++;

	smp_mb();
	if (lo->lo_bio_cnt > 8) {
		if (timer_pending(&lo->lo_bio_timer))
			del_timer(&lo->lo_bio_timer);

		if (waitqueue_active(&lo->lo_event))
			wake_up(&lo->lo_event);
	} else if (!timer_pending(&lo->lo_bio_timer)) {
		lo->lo_bio_timer.expires = jiffies + 1;
		add_timer(&lo->lo_bio_timer);
	}
}

/*
 * Grab first pending buffer
 */
static struct bio *loop_get_bio(struct loop_device *lo)
{
	struct bio *bio;

	if ((bio = lo->lo_bio)) {
		if (bio == lo->lo_biotail)
			lo->lo_biotail = NULL;
		lo->lo_bio = bio->bi_next;
		bio->bi_next = NULL;
	}

	return bio;
}

static void loop_exit_fastfs(struct loop_device *lo)
{
	struct inode *inode = lo->lo_backing_file->f_mapping->host;

	/*
	 * drop what page cache we instantiated filling holes
	 */
	invalidate_inode_pages2(lo->lo_backing_file->f_mapping);

	blk_queue_ordered(lo->lo_queue, QUEUE_ORDERED_NONE, NULL);

	mutex_lock(&inode->i_mutex);
	inode->i_flags &= ~S_SWAPFILE;
	mutex_unlock(&inode->i_mutex);
}

static inline u64 lo_bio_offset(struct loop_device *lo, struct bio *bio)
{
	return (u64)lo->lo_offset + ((u64)bio->bi_sector << 9);
}

/*
 * Find extent mapping this lo device block to the file block on the real
 * device
 */
static struct extent_map *loop_lookup_extent(struct loop_device *lo,
					     u64 offset, gfp_t gfp_mask)
{
	struct address_space *mapping = lo->lo_backing_file->f_mapping;
	u64 len = 1 << lo->blkbits;

	return mapping->a_ops->map_extent(mapping, NULL, 0, offset, len, 0,
						gfp_mask);
}

static void end_bio_hole_filling(struct bio *bio, int err)
{
	struct address_space *mapping = bio->bi_bdev->bd_inode->i_mapping;
	struct bio *orig_bio = bio->bi_private;

	if (mapping->a_ops->extent_io_complete) {
		u64 start = orig_bio->bi_sector << 9;
		u64 len = bio->bi_size;

		mapping->a_ops->extent_io_complete(mapping, start, len);
	}

	bio_put(bio);
	bio_endio(orig_bio, err);
}

static void fill_extent_hole(struct loop_device *lo, struct bio *bio)
{
	struct address_space *mapping = lo->lo_backing_file->f_mapping;
	struct bio *new_bio;
	struct extent_map *em;
	u64 len = bio->bi_size;
	u64 start = lo_bio_offset(lo, bio);
	u64 disk_block;
	u64 extent_off;

	/*
	 * change the sector so we can find the correct file offset in our
	 * endio
	 */
	bio->bi_sector = start >> 9;

	mutex_lock(&mapping->host->i_mutex);

	em = mapping->a_ops->map_extent(mapping, NULL, 0,
					start, len, 1, GFP_KERNEL);
	mark_inode_dirty(mapping->host);
	mutex_unlock(&mapping->host->i_mutex);

	if (em && !IS_ERR(em)) {
		disk_block = em->block_start;
		extent_off = start - em->start;

		/*
		 * bio_clone() is mempool backed, so if __GFP_WAIT is set
		 * it wont ever fail
		 */
		new_bio = bio_clone(bio, GFP_NOIO);
		new_bio->bi_sector = (disk_block + extent_off) >> 9;
		new_bio->bi_bdev = em->bdev;
		new_bio->bi_private = bio;
		new_bio->bi_size = bio->bi_size;
		new_bio->bi_end_io = end_bio_hole_filling;
		free_extent_map(em);

		generic_make_request(new_bio);
	} else
		bio_endio(bio, -EIO);
}

static void loop_bio_destructor(struct bio *bio)
{
	struct completion *c = (struct completion *) bio->bi_flags;

	complete(c);
}

/*
 * Alloc a hint bio to tell the loop thread to read file blocks for a given
 * range
 */
static void loop_schedule_extent_mapping(struct loop_device *lo,
					 struct bio *old_bio)
{
	DECLARE_COMPLETION_ONSTACK(comp);
	struct bio *bio, stackbio;
	int do_sync = 0;

	bio = bio_alloc(GFP_ATOMIC, 0);
	if (!bio) {
		bio = &stackbio;
		bio_init(bio);
		bio->bi_destructor = loop_bio_destructor;
		bio->bi_flags = (unsigned long) &comp;
		do_sync = 1;
	}

	bio->bi_rw = LOOP_EXTENT_RW_MAGIC;
	bio->bi_private = old_bio;

	loop_add_bio(lo, bio);

	if (do_sync) {
		spin_unlock_irq(&lo->lo_lock);
		wait_for_completion(&comp);
		spin_lock_irq(&lo->lo_lock);
	}
}

static void loop_handle_extent_hole(struct loop_device *lo, struct bio *bio,
				    int sync)
{
	/*
	 * for a read, just zero the data and end the io
	 */
	if (bio_data_dir(bio) == READ) {
		struct bio_vec *bvec;
		unsigned long flags;
		int i;

		bio_for_each_segment(bvec, bio, i) {
			char *dst = bvec_kmap_irq(bvec, &flags);

			memset(dst, 0, bvec->bv_len);
			bvec_kunmap_irq(dst, &flags);
		}
		bio_endio(bio, 0);
	} else {
		/*
		 * let the page cache handling path do this bio, and then
		 * lookup the mapped blocks after the io has been issued to
		 * instantiate extents.
		 */
		if (!sync)
			loop_add_bio(lo, bio);
		else
			fill_extent_hole(lo, bio);
	}
}

static inline int lo_is_switch_bio(struct bio *bio)
{
	return !bio->bi_bdev && bio->bi_rw == LOOP_SWITCH_RW_MAGIC;
}

static inline int lo_is_map_bio(struct bio *bio)
{
	return !bio->bi_bdev && bio->bi_rw == LOOP_EXTENT_RW_MAGIC;
}

static int __loop_redirect_bio(struct loop_device *lo, struct extent_map *em,
			       struct bio *bio, int sync)
{
	u64 extent_off;
	u64 disk_block;

	/*
	 * handle sparse io
	 */
	if (em->block_start == EXTENT_MAP_HOLE) {
		loop_handle_extent_hole(lo, bio, sync);
		free_extent_map(em);
		return 0;
	}

	/*
	 * not a hole, redirect
	 */
	disk_block = em->block_start;
	extent_off = lo_bio_offset(lo, bio) - em->start;
	bio->bi_bdev = em->bdev;
	bio->bi_sector = (disk_block + extent_off) >> 9;
	free_extent_map(em);
	return 1;
}

/*
 * Change mapping of the bio, so that it points to the real bdev and offset
 */
static int loop_redirect_bio(struct loop_device *lo, struct bio *bio)
{
	u64 start = lo_bio_offset(lo, bio);
	struct extent_map *em;

	em = loop_lookup_extent(lo, start, GFP_ATOMIC);
	if (IS_ERR(em)) {
		bio_endio(bio, PTR_ERR(em));
		return 0;
	} else if (!em) {
		loop_schedule_extent_mapping(lo, bio);
		return 0;
	}

	return __loop_redirect_bio(lo, em, bio, 0);
}

/*
 * Wait on bio's on our list to complete before sending a barrier bio
 * to the below device. Called with lo_lock held.
 */
static void loop_wait_on_bios(struct loop_device *lo)
{
	__lo_throttle(&lo->lo_bio_wait, &lo->lo_lock, !lo->lo_bio);
}

static void loop_wait_on_switch(struct loop_device *lo)
{
	__lo_throttle(&lo->lo_bio_wait, &lo->lo_lock, !lo->lo_switch);
}

static int loop_make_request(struct request_queue *q, struct bio *old_bio)
{
	struct loop_device *lo = q->queuedata;
	int rw = bio_rw(old_bio);

	if (rw == READA)
		rw = READ;

	BUG_ON(!lo || (rw != READ && rw != WRITE));

	spin_lock_irq(&lo->lo_lock);
	if (lo->lo_state != Lo_bound)
		goto out;
	if (unlikely(rw == WRITE && (lo->lo_flags & LO_FLAGS_READ_ONLY)))
		goto out;
	if (lo->lo_flags & LO_FLAGS_FASTFS) {
		/*
		 * If we get a barrier bio, then we just need to wait for
		 * existing bio's to be complete. This can only happen
		 * on the 'new' extent mapped loop, since that is the only
		 * one that supports barriers.
		 */
		if (bio_barrier(old_bio))
			loop_wait_on_bios(lo);

		/*
		 * if file switch is in progress, wait for it to complete
		 */
		if (!lo_is_switch_bio(old_bio) && lo->lo_switch)
			loop_wait_on_switch(lo);

		if (loop_redirect_bio(lo, old_bio))
			goto out_redir;
		goto out_end;
	}
	loop_add_bio(lo, old_bio);
	spin_unlock_irq(&lo->lo_lock);
	return 0;

out:
	bio_io_error(old_bio);
out_end:
	spin_unlock_irq(&lo->lo_lock);
	return 0;

out_redir:
	spin_unlock_irq(&lo->lo_lock);
	return 1;
}

/*
 * kick off io on the underlying address space
 */
static void loop_unplug(struct request_queue *q)
{
	struct loop_device *lo = q->queuedata;

	queue_flag_clear_unlocked(QUEUE_FLAG_PLUGGED, q);
	blk_run_address_space(lo->lo_backing_file->f_mapping);
}

static void loop_unplug_fastfs(struct request_queue *q)
{
	struct loop_device *lo = q->queuedata;
	struct request_queue *rq = bdev_get_queue(lo->fs_bdev);
	unsigned long flags;

	local_irq_save(flags);

	if (blk_remove_plug(q) && rq->unplug_fn)
		rq->unplug_fn(rq);

	local_irq_restore(flags);
}

struct switch_request {
	struct file *file;
	struct completion wait;
};

static void do_loop_switch(struct loop_device *, struct switch_request *);
static int loop_init_fastfs(struct loop_device *);

static inline void loop_handle_bio(struct loop_device *lo, struct bio *bio)
{
	if (lo_is_map_bio(bio)) {
		struct bio *org_bio = bio->bi_private;
		struct extent_map *em;

		em = loop_lookup_extent(lo, lo_bio_offset(lo, org_bio),
					 GFP_KERNEL);

		if (__loop_redirect_bio(lo, em, org_bio, 1))
			generic_make_request(org_bio);

		bio_put(bio);
	} else if (lo_is_switch_bio(bio)) {
		do_loop_switch(lo, bio->bi_private);
		bio_put(bio);
	} else {
		if (lo->lo_flags & LO_FLAGS_FASTFS) {
			/* we only get here when filling holes */
			fill_extent_hole(lo, bio);
		} else {
			int ret = do_bio_filebacked(lo, bio);

			bio_endio(bio, ret);
		}
	}
}

/*
 * worker thread that handles reads/writes to file backed loop devices,
 * to avoid blocking in our make_request_fn. it also does loop decrypting
 * on reads for block backed loop, as that is too heavy to do from
 * b_end_io context where irqs may be disabled.
 *
 * Loop explanation:  loop_clr_fd() sets lo_state to Lo_rundown before
 * calling kthread_stop().  Therefore once kthread_should_stop() is
 * true, make_request will not place any more requests.  Therefore
 * once kthread_should_stop() is true and lo_bio is NULL, we are
 * done with the loop.
 */
static int loop_thread(void *data)
{
	struct loop_device *lo = data;
	struct bio *bio;

	set_user_nice(current, -20);

	while (!kthread_should_stop() || lo->lo_bio) {

		wait_event_interruptible(lo->lo_event,
				lo->lo_bio || kthread_should_stop());
		if (!lo->lo_bio)
			continue;
		spin_lock_irq(&lo->lo_lock);
		bio = loop_get_bio(lo);
		spin_unlock_irq(&lo->lo_lock);

		BUG_ON(!bio);

		loop_handle_bio(lo, bio);

		spin_lock_irq(&lo->lo_lock);
		if (--lo->lo_bio_cnt < LO_BIO_THROTTLE_LOW || !lo->lo_bio)
			wake_up(&lo->lo_bio_wait);
		spin_unlock_irq(&lo->lo_lock);
	}

	return 0;
}

/*
 * loop_switch performs the hard work of switching a backing store.
 * First it needs to flush existing IO, it does this by sending a magic
 * BIO down the pipe. The completion of this BIO does the actual switch.
 */
static int loop_switch(struct loop_device *lo, struct file *file)
{
	struct switch_request w;
	struct bio *bio = bio_alloc(GFP_KERNEL, 0);
	if (!bio)
		return -ENOMEM;
	init_completion(&w.wait);
	w.file = file;
	bio->bi_private = &w;
	bio->bi_bdev = NULL;
	bio->bi_rw = LOOP_SWITCH_RW_MAGIC;
	lo->lo_switch = 1;
	loop_make_request(lo->lo_queue, bio);
	wait_for_completion(&w.wait);
	return 0;
}

/*
 * Helper to flush the IOs in loop, but keeping loop thread running
 */
static int loop_flush(struct loop_device *lo)
{
	/* loop not yet configured, no running thread, nothing to flush */
	if (!lo->lo_thread)
		return 0;

	return loop_switch(lo, NULL);
}

/*
 * Do the actual switch; called from the BIO completion routine
 */
static void do_loop_switch(struct loop_device *lo, struct switch_request *p)
{
	struct file *file = p->file;
	struct file *old_file = lo->lo_backing_file;
	struct address_space *mapping;
	const int fastfs = lo->lo_flags & LO_FLAGS_FASTFS;

	/* if no new file, only flush of queued bios requested */
	if (!file)
		goto out;

	if (fastfs)
		loop_exit_fastfs(lo);
 
	mapping = file->f_mapping;
	mapping_set_gfp_mask(old_file->f_mapping, lo->old_gfp_mask);
	lo->lo_backing_file = file;
	lo->lo_blocksize = S_ISBLK(mapping->host->i_mode) ?
		mapping->host->i_bdev->bd_block_size : PAGE_SIZE;
	lo->old_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping, lo->old_gfp_mask & ~(__GFP_IO|__GFP_FS));

	if (fastfs)
		loop_init_fastfs(lo);

	lo->lo_switch = 0;
	wake_up(&lo->lo_bio_wait);
out:
	complete(&p->wait);
}


/*
 * loop_change_fd switched the backing store of a loopback device to
 * a new file. This is useful for operating system installers to free up
 * the original file and in High Availability environments to switch to
 * an alternative location for the content in case of server meltdown.
 * This can only work if the loop device is used read-only, and if the
 * new backing store is the same size and type as the old backing store.
 */
static int loop_change_fd(struct loop_device *lo, struct block_device *bdev,
			  unsigned int arg)
{
	struct file	*file, *old_file;
	struct inode	*inode;
	int		error;

	error = -ENXIO;
	if (lo->lo_state != Lo_bound)
		goto out;

	/* the loop device has to be read-only */
	error = -EINVAL;
	if (!(lo->lo_flags & LO_FLAGS_READ_ONLY))
		goto out;

	error = -EBADF;
	file = fget(arg);
	if (!file)
		goto out;

	inode = file->f_mapping->host;
	old_file = lo->lo_backing_file;

	error = -EINVAL;

	if (!S_ISREG(inode->i_mode) && !S_ISBLK(inode->i_mode))
		goto out_putf;

	/* new backing store needs to support loop (eg splice_read) */
	if (!inode->i_fop->splice_read)
		goto out_putf;

	/* size of the new backing store needs to be the same */
	if (get_loop_size(lo, file) != get_loop_size(lo, old_file))
		goto out_putf;

	/* and ... switch */
	error = loop_switch(lo, file);
	if (error)
		goto out_putf;

	fput(old_file);
	if (max_part > 0)
		ioctl_by_bdev(bdev, BLKRRPART, 0);
	return 0;

 out_putf:
	fput(file);
 out:
	return error;
}

/*
 * See if adding this bvec would cause us to spill into a new extent. If so,
 * disallow the add to start a new bio. This ensures that the bio we receive
 * in loop_make_request() never spans two extents or more.
 */
static int loop_merge_bvec(struct request_queue *q, struct bvec_merge_data *bvm,
			   struct bio_vec *bvec)
{
	struct loop_device *lo = q->queuedata;
	struct extent_map *em;
	unsigned int ret;
	u64 start;
	u64 len;

	if (!bvm->bi_size)
		return bvec->bv_len;

	start = (u64) lo->lo_offset + ((u64)bvm->bi_sector << 9);
	len = bvm->bi_size + bvec->bv_len;
	ret = bvec->bv_len;

	em = loop_lookup_extent(lo, start, GFP_ATOMIC);
	if (em && !IS_ERR(em)) {
		/*
		 * have extent, disallow if outside that extent
		 */
		if (start + len > em->start + em->len || start < em->start)
			ret = 0;

		free_extent_map(em);
	} else
		ret = 0;

	return ret;
}

/*
 * Initialize the members pertaining to extent mapping. We will populate
 * the tree lazily on demand, as a full scan of a big file can take some
 * time.
 */
static int loop_init_fastfs(struct loop_device *lo)
{
	struct file *file = lo->lo_backing_file;
	struct inode *inode = file->f_mapping->host;
	struct request_queue *fs_q;
	int ret;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	/*
	 * Need a working extent_map
	 */
	if (inode->i_mapping->a_ops->map_extent == NULL)
		return -EINVAL;
	/*
	 * invalidate all page cache belonging to this file, it could become
	 * stale when we directly overwrite blocks.
	 */
	ret = invalidate_inode_pages2(file->f_mapping);
	if (unlikely(ret))
		return ret;

	/*
	 * disable truncate on this file
	 */
	mutex_lock(&inode->i_mutex);
	inode->i_flags |= S_SWAPFILE;
	mutex_unlock(&inode->i_mutex);

	lo->blkbits = inode->i_blkbits;
	lo->fs_bdev = file->f_mapping->host->i_sb->s_bdev;
	lo->lo_flags |= LO_FLAGS_FASTFS;
	lo->lo_queue->unplug_fn = loop_unplug_fastfs;

	blk_queue_merge_bvec(lo->lo_queue, loop_merge_bvec);
	blk_queue_ordered(lo->lo_queue, QUEUE_ORDERED_DRAIN, NULL);

	fs_q = bdev_get_queue(lo->fs_bdev);
	blk_queue_stack_limits(lo->lo_queue, fs_q);

	printk(KERN_INFO "loop%d: fast redirect\n", lo->lo_number);
	return 0;
}

static inline int is_loop_device(struct file *file)
{
	struct inode *i = file->f_mapping->host;

	return i && S_ISBLK(i->i_mode) && MAJOR(i->i_rdev) == LOOP_MAJOR;
}

static int loop_set_fd(struct loop_device *lo, fmode_t mode,
		       struct block_device *bdev, unsigned int arg)
{
	struct file	*file, *f;
	struct inode	*inode;
	struct address_space *mapping;
	unsigned lo_blocksize;
	int		lo_flags = 0;
	int		error;
	loff_t		size;

	/* This is safe, since we have a reference from open(). */
	__module_get(THIS_MODULE);

	error = -EBADF;
	file = fget(arg);
	if (!file)
		goto out;

	error = -EBUSY;
	if (lo->lo_state != Lo_unbound)
		goto out_putf;

	/* Avoid recursion */
	f = file;
	while (is_loop_device(f)) {
		struct loop_device *l;

		if (f->f_mapping->host->i_bdev == bdev)
			goto out_putf;

		l = f->f_mapping->host->i_bdev->bd_disk->private_data;
		if (l->lo_state == Lo_unbound) {
			error = -EINVAL;
			goto out_putf;
		}
		f = l->lo_backing_file;
	}

	mapping = file->f_mapping;
	inode = mapping->host;
	lo->lo_flags = 0;

	if (!(file->f_mode & FMODE_WRITE))
		lo_flags |= LO_FLAGS_READ_ONLY;

	error = -EINVAL;
	if (S_ISREG(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		const struct address_space_operations *aops = mapping->a_ops;
		/*
		 * If we can't read - sorry. If we only can't write - well,
		 * it's going to be read-only.
		 */
		if (!file->f_op->splice_read)
			goto out_putf;
		if (aops->write_begin)
			lo_flags |= LO_FLAGS_USE_AOPS;
		if (!(lo_flags & LO_FLAGS_USE_AOPS) && !file->f_op->write)
			lo_flags |= LO_FLAGS_READ_ONLY;

		lo_blocksize = S_ISBLK(inode->i_mode) ?
			inode->i_bdev->bd_block_size : PAGE_SIZE;

		error = 0;
	} else {
		goto out_putf;
	}

	size = get_loop_size(lo, file);

	if ((loff_t)(sector_t)size != size) {
		error = -EFBIG;
		goto out_putf;
	}

	if (!(mode & FMODE_WRITE))
		lo_flags |= LO_FLAGS_READ_ONLY;

	set_device_ro(bdev, (lo_flags & LO_FLAGS_READ_ONLY) != 0);

	lo->lo_blocksize = lo_blocksize;
	lo->lo_device = bdev;
	lo->lo_flags = lo_flags;
	lo->lo_backing_file = file;
	lo->transfer = transfer_none;
	lo->ioctl = NULL;
	lo->lo_sizelimit = 0;
	lo->old_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping, lo->old_gfp_mask & ~(__GFP_IO|__GFP_FS));

	lo->lo_bio = lo->lo_biotail = NULL;

	/*
	 * set queue make_request_fn, and add limits based on lower level
	 * device
	 */
	blk_queue_make_request(lo->lo_queue, loop_make_request);
	lo->lo_queue->queuedata = lo;
	lo->lo_queue->unplug_fn = loop_unplug;

	set_capacity(lo->lo_disk, size);
	bd_set_size(bdev, size << 9);

	set_blocksize(bdev, lo_blocksize);

	/*
	 * This needs to be done after setup with another ioctl,
	 * not automatically like this.
	 */
	loop_init_fastfs(lo);

	lo->lo_thread = kthread_create(loop_thread, lo, "loop%d",
						lo->lo_number);
	if (IS_ERR(lo->lo_thread)) {
		error = PTR_ERR(lo->lo_thread);
		goto out_clr;
	}
	lo->lo_state = Lo_bound;
	wake_up_process(lo->lo_thread);
	if (max_part > 0)
		ioctl_by_bdev(bdev, BLKRRPART, 0);
	return 0;

out_clr:
	lo->lo_thread = NULL;
	lo->lo_device = NULL;
	lo->lo_backing_file = NULL;
	lo->lo_flags = 0;
	set_capacity(lo->lo_disk, 0);
	invalidate_bdev(bdev);
	bd_set_size(bdev, 0);
	mapping_set_gfp_mask(mapping, lo->old_gfp_mask);
	lo->lo_state = Lo_unbound;
 out_putf:
	fput(file);
 out:
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);
	return error;
}

static int
loop_release_xfer(struct loop_device *lo)
{
	int err = 0;
	struct loop_func_table *xfer = lo->lo_encryption;

	if (xfer) {
		if (xfer->release)
			err = xfer->release(lo);
		lo->transfer = NULL;
		lo->lo_encryption = NULL;
		module_put(xfer->owner);
	}
	return err;
}

static int
loop_init_xfer(struct loop_device *lo, struct loop_func_table *xfer,
	       const struct loop_info64 *i)
{
	int err = 0;

	if (xfer) {
		struct module *owner = xfer->owner;

		if (!try_module_get(owner))
			return -EINVAL;
		if (xfer->init)
			err = xfer->init(lo, i);
		if (err)
			module_put(owner);
		else
			lo->lo_encryption = xfer;
	}
	return err;
}

static int loop_clr_fd(struct loop_device *lo, struct block_device *bdev)
{
	struct file *filp = lo->lo_backing_file;
	gfp_t gfp = lo->old_gfp_mask;

	if (lo->lo_state != Lo_bound)
		return -ENXIO;

	if (lo->lo_refcnt > 1)	/* we needed one fd for the ioctl */
		return -EBUSY;

	if (filp == NULL)
		return -EINVAL;

	spin_lock_irq(&lo->lo_lock);
	lo->lo_state = Lo_rundown;
	spin_unlock_irq(&lo->lo_lock);

	kthread_stop(lo->lo_thread);

	if (lo->lo_flags & LO_FLAGS_FASTFS)
		loop_exit_fastfs(lo);

	lo->lo_queue->unplug_fn = NULL;
	lo->lo_backing_file = NULL;

	loop_release_xfer(lo);
	lo->transfer = NULL;
	lo->ioctl = NULL;
	lo->lo_device = NULL;
	lo->lo_encryption = NULL;
	lo->lo_offset = 0;
	lo->lo_sizelimit = 0;
	lo->lo_encrypt_key_size = 0;
	lo->lo_flags = 0;
	lo->lo_thread = NULL;
	memset(lo->lo_encrypt_key, 0, LO_KEY_SIZE);
	memset(lo->lo_crypt_name, 0, LO_NAME_SIZE);
	memset(lo->lo_file_name, 0, LO_NAME_SIZE);
	if (bdev)
		invalidate_bdev(bdev);
	set_capacity(lo->lo_disk, 0);
	if (bdev)
		bd_set_size(bdev, 0);
	mapping_set_gfp_mask(filp->f_mapping, gfp);
	lo->lo_state = Lo_unbound;
	fput(filp);
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);
	if (max_part > 0)
		ioctl_by_bdev(bdev, BLKRRPART, 0);
	return 0;
}

static int
loop_set_status(struct loop_device *lo, const struct loop_info64 *info)
{
	int err;
	struct loop_func_table *xfer;
	uid_t uid = current_uid();

	if (lo->lo_encrypt_key_size &&
	    lo->lo_key_owner != uid &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (lo->lo_state != Lo_bound)
		return -ENXIO;
	if ((unsigned int) info->lo_encrypt_key_size > LO_KEY_SIZE)
		return -EINVAL;

	err = loop_release_xfer(lo);
	if (err)
		return err;

	if (info->lo_encrypt_type) {
		unsigned int type = info->lo_encrypt_type;

		if (lo->lo_flags & LO_FLAGS_FASTFS)
			return -EINVAL;

		if (type >= MAX_LO_CRYPT)
			return -EINVAL;
		xfer = xfer_funcs[type];
		if (xfer == NULL)
			return -EINVAL;
	} else
		xfer = NULL;

	/*
	 * for remaps, offset must be a multiple of full blocks
	 */
	if ((lo->lo_flags & LO_FLAGS_FASTFS) &&
	    (((1 << lo->blkbits) - 1) & info->lo_offset))
		return -EINVAL;

	err = loop_init_xfer(lo, xfer, info);
	if (err)
		return err;

	if (lo->lo_offset != info->lo_offset ||
	    lo->lo_sizelimit != info->lo_sizelimit) {
		lo->lo_offset = info->lo_offset;
		lo->lo_sizelimit = info->lo_sizelimit;
		if (figure_loop_size(lo))
			return -EFBIG;
	}

	memcpy(lo->lo_file_name, info->lo_file_name, LO_NAME_SIZE);
	memcpy(lo->lo_crypt_name, info->lo_crypt_name, LO_NAME_SIZE);
	lo->lo_file_name[LO_NAME_SIZE-1] = 0;
	lo->lo_crypt_name[LO_NAME_SIZE-1] = 0;

	if (!xfer)
		xfer = &none_funcs;
	lo->transfer = xfer->transfer;
	lo->ioctl = xfer->ioctl;

	if ((lo->lo_flags & LO_FLAGS_AUTOCLEAR) !=
	     (info->lo_flags & LO_FLAGS_AUTOCLEAR))
		lo->lo_flags ^= LO_FLAGS_AUTOCLEAR;

	lo->lo_encrypt_key_size = info->lo_encrypt_key_size;
	lo->lo_init[0] = info->lo_init[0];
	lo->lo_init[1] = info->lo_init[1];
	if (info->lo_encrypt_key_size) {
		memcpy(lo->lo_encrypt_key, info->lo_encrypt_key,
		       info->lo_encrypt_key_size);
		lo->lo_key_owner = uid;
	}	

	return 0;
}

static int
loop_get_status(struct loop_device *lo, struct loop_info64 *info)
{
	struct file *file = lo->lo_backing_file;
	struct kstat stat;
	int error;

	if (lo->lo_state != Lo_bound)
		return -ENXIO;
	error = vfs_getattr(file->f_path.mnt, file->f_path.dentry, &stat);
	if (error)
		return error;
	memset(info, 0, sizeof(*info));
	info->lo_number = lo->lo_number;
	info->lo_device = huge_encode_dev(stat.dev);
	info->lo_inode = stat.ino;
	info->lo_rdevice = huge_encode_dev(lo->lo_device ? stat.rdev : stat.dev);
	info->lo_offset = lo->lo_offset;
	info->lo_sizelimit = lo->lo_sizelimit;
	info->lo_flags = lo->lo_flags;
	memcpy(info->lo_file_name, lo->lo_file_name, LO_NAME_SIZE);
	memcpy(info->lo_crypt_name, lo->lo_crypt_name, LO_NAME_SIZE);
	info->lo_encrypt_type =
		lo->lo_encryption ? lo->lo_encryption->number : 0;
	if (lo->lo_encrypt_key_size && capable(CAP_SYS_ADMIN)) {
		info->lo_encrypt_key_size = lo->lo_encrypt_key_size;
		memcpy(info->lo_encrypt_key, lo->lo_encrypt_key,
		       lo->lo_encrypt_key_size);
	}
	return 0;
}

static void
loop_info64_from_old(const struct loop_info *info, struct loop_info64 *info64)
{
	memset(info64, 0, sizeof(*info64));
	info64->lo_number = info->lo_number;
	info64->lo_device = info->lo_device;
	info64->lo_inode = info->lo_inode;
	info64->lo_rdevice = info->lo_rdevice;
	info64->lo_offset = info->lo_offset;
	info64->lo_sizelimit = 0;
	info64->lo_encrypt_type = info->lo_encrypt_type;
	info64->lo_encrypt_key_size = info->lo_encrypt_key_size;
	info64->lo_flags = info->lo_flags;
	info64->lo_init[0] = info->lo_init[0];
	info64->lo_init[1] = info->lo_init[1];
	if (info->lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info64->lo_crypt_name, info->lo_name, LO_NAME_SIZE);
	else
		memcpy(info64->lo_file_name, info->lo_name, LO_NAME_SIZE);
	memcpy(info64->lo_encrypt_key, info->lo_encrypt_key, LO_KEY_SIZE);
}

static int
loop_info64_to_old(const struct loop_info64 *info64, struct loop_info *info)
{
	memset(info, 0, sizeof(*info));
	info->lo_number = info64->lo_number;
	info->lo_device = info64->lo_device;
	info->lo_inode = info64->lo_inode;
	info->lo_rdevice = info64->lo_rdevice;
	info->lo_offset = info64->lo_offset;
	info->lo_encrypt_type = info64->lo_encrypt_type;
	info->lo_encrypt_key_size = info64->lo_encrypt_key_size;
	info->lo_flags = info64->lo_flags;
	info->lo_init[0] = info64->lo_init[0];
	info->lo_init[1] = info64->lo_init[1];
	if (info->lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info->lo_name, info64->lo_crypt_name, LO_NAME_SIZE);
	else
		memcpy(info->lo_name, info64->lo_file_name, LO_NAME_SIZE);
	memcpy(info->lo_encrypt_key, info64->lo_encrypt_key, LO_KEY_SIZE);

	/* error in case values were truncated */
	if (info->lo_device != info64->lo_device ||
	    info->lo_rdevice != info64->lo_rdevice ||
	    info->lo_inode != info64->lo_inode ||
	    info->lo_offset != info64->lo_offset)
		return -EOVERFLOW;

	return 0;
}

static int
loop_set_status_old(struct loop_device *lo, const struct loop_info __user *arg)
{
	struct loop_info info;
	struct loop_info64 info64;

	if (copy_from_user(&info, arg, sizeof (struct loop_info)))
		return -EFAULT;
	loop_info64_from_old(&info, &info64);
	return loop_set_status(lo, &info64);
}

static int
loop_set_status64(struct loop_device *lo, const struct loop_info64 __user *arg)
{
	struct loop_info64 info64;

	if (copy_from_user(&info64, arg, sizeof (struct loop_info64)))
		return -EFAULT;
	return loop_set_status(lo, &info64);
}

static int
loop_get_status_old(struct loop_device *lo, struct loop_info __user *arg) {
	struct loop_info info;
	struct loop_info64 info64;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = loop_get_status(lo, &info64);
	if (!err)
		err = loop_info64_to_old(&info64, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info)))
		err = -EFAULT;

	return err;
}

static int
loop_get_status64(struct loop_device *lo, struct loop_info64 __user *arg) {
	struct loop_info64 info64;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = loop_get_status(lo, &info64);
	if (!err && copy_to_user(arg, &info64, sizeof(info64)))
		err = -EFAULT;

	return err;
}

static int lo_ioctl(struct block_device *bdev, fmode_t mode,
	unsigned int cmd, unsigned long arg)
{
	struct loop_device *lo = bdev->bd_disk->private_data;
	int err;

	mutex_lock(&lo->lo_ctl_mutex);
	switch (cmd) {
	case LOOP_SET_FD:
		err = loop_set_fd(lo, mode, bdev, arg);
		break;
	case LOOP_CHANGE_FD:
		err = loop_change_fd(lo, bdev, arg);
		break;
	case LOOP_CLR_FD:
		err = loop_clr_fd(lo, bdev);
		break;
	case LOOP_SET_STATUS:
		err = loop_set_status_old(lo, (struct loop_info __user *) arg);
		break;
	case LOOP_GET_STATUS:
		err = loop_get_status_old(lo, (struct loop_info __user *) arg);
		break;
	case LOOP_SET_STATUS64:
		err = loop_set_status64(lo, (struct loop_info64 __user *) arg);
		break;
	case LOOP_GET_STATUS64:
		err = loop_get_status64(lo, (struct loop_info64 __user *) arg);
		break;
	case LOOP_SET_FASTFS:
		err = loop_init_fastfs(lo);
		break;
	default:
		err = lo->ioctl ? lo->ioctl(lo, cmd, arg) : -EINVAL;
	}
	mutex_unlock(&lo->lo_ctl_mutex);
	return err;
}

#ifdef CONFIG_COMPAT
struct compat_loop_info {
	compat_int_t	lo_number;      /* ioctl r/o */
	compat_dev_t	lo_device;      /* ioctl r/o */
	compat_ulong_t	lo_inode;       /* ioctl r/o */
	compat_dev_t	lo_rdevice;     /* ioctl r/o */
	compat_int_t	lo_offset;
	compat_int_t	lo_encrypt_type;
	compat_int_t	lo_encrypt_key_size;    /* ioctl w/o */
	compat_int_t	lo_flags;       /* ioctl r/o */
	char		lo_name[LO_NAME_SIZE];
	unsigned char	lo_encrypt_key[LO_KEY_SIZE]; /* ioctl w/o */
	compat_ulong_t	lo_init[2];
	char		reserved[4];
};

/*
 * Transfer 32-bit compatibility structure in userspace to 64-bit loop info
 * - noinlined to reduce stack space usage in main part of driver
 */
static noinline int
loop_info64_from_compat(const struct compat_loop_info __user *arg,
			struct loop_info64 *info64)
{
	struct compat_loop_info info;

	if (copy_from_user(&info, arg, sizeof(info)))
		return -EFAULT;

	memset(info64, 0, sizeof(*info64));
	info64->lo_number = info.lo_number;
	info64->lo_device = info.lo_device;
	info64->lo_inode = info.lo_inode;
	info64->lo_rdevice = info.lo_rdevice;
	info64->lo_offset = info.lo_offset;
	info64->lo_sizelimit = 0;
	info64->lo_encrypt_type = info.lo_encrypt_type;
	info64->lo_encrypt_key_size = info.lo_encrypt_key_size;
	info64->lo_flags = info.lo_flags;
	info64->lo_init[0] = info.lo_init[0];
	info64->lo_init[1] = info.lo_init[1];
	if (info.lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info64->lo_crypt_name, info.lo_name, LO_NAME_SIZE);
	else
		memcpy(info64->lo_file_name, info.lo_name, LO_NAME_SIZE);
	memcpy(info64->lo_encrypt_key, info.lo_encrypt_key, LO_KEY_SIZE);
	return 0;
}

/*
 * Transfer 64-bit loop info to 32-bit compatibility structure in userspace
 * - noinlined to reduce stack space usage in main part of driver
 */
static noinline int
loop_info64_to_compat(const struct loop_info64 *info64,
		      struct compat_loop_info __user *arg)
{
	struct compat_loop_info info;

	memset(&info, 0, sizeof(info));
	info.lo_number = info64->lo_number;
	info.lo_device = info64->lo_device;
	info.lo_inode = info64->lo_inode;
	info.lo_rdevice = info64->lo_rdevice;
	info.lo_offset = info64->lo_offset;
	info.lo_encrypt_type = info64->lo_encrypt_type;
	info.lo_encrypt_key_size = info64->lo_encrypt_key_size;
	info.lo_flags = info64->lo_flags;
	info.lo_init[0] = info64->lo_init[0];
	info.lo_init[1] = info64->lo_init[1];
	if (info.lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info.lo_name, info64->lo_crypt_name, LO_NAME_SIZE);
	else
		memcpy(info.lo_name, info64->lo_file_name, LO_NAME_SIZE);
	memcpy(info.lo_encrypt_key, info64->lo_encrypt_key, LO_KEY_SIZE);

	/* error in case values were truncated */
	if (info.lo_device != info64->lo_device ||
	    info.lo_rdevice != info64->lo_rdevice ||
	    info.lo_inode != info64->lo_inode ||
	    info.lo_offset != info64->lo_offset ||
	    info.lo_init[0] != info64->lo_init[0] ||
	    info.lo_init[1] != info64->lo_init[1])
		return -EOVERFLOW;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

static int
loop_set_status_compat(struct loop_device *lo,
		       const struct compat_loop_info __user *arg)
{
	struct loop_info64 info64;
	int ret;

	ret = loop_info64_from_compat(arg, &info64);
	if (ret < 0)
		return ret;
	return loop_set_status(lo, &info64);
}

static int
loop_get_status_compat(struct loop_device *lo,
		       struct compat_loop_info __user *arg)
{
	struct loop_info64 info64;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = loop_get_status(lo, &info64);
	if (!err)
		err = loop_info64_to_compat(&info64, arg);
	return err;
}

static int lo_compat_ioctl(struct block_device *bdev, fmode_t mode,
			   unsigned int cmd, unsigned long arg)
{
	struct loop_device *lo = bdev->bd_disk->private_data;
	int err;

	switch(cmd) {
	case LOOP_SET_STATUS:
		mutex_lock(&lo->lo_ctl_mutex);
		err = loop_set_status_compat(
			lo, (const struct compat_loop_info __user *) arg);
		mutex_unlock(&lo->lo_ctl_mutex);
		break;
	case LOOP_GET_STATUS:
		mutex_lock(&lo->lo_ctl_mutex);
		err = loop_get_status_compat(
			lo, (struct compat_loop_info __user *) arg);
		mutex_unlock(&lo->lo_ctl_mutex);
		break;
	case LOOP_CLR_FD:
	case LOOP_GET_STATUS64:
	case LOOP_SET_STATUS64:
		arg = (unsigned long) compat_ptr(arg);
	case LOOP_SET_FD:
	case LOOP_CHANGE_FD:
		err = lo_ioctl(bdev, mode, cmd, arg);
		break;
	default:
		err = -ENOIOCTLCMD;
		break;
	}
	return err;
}
#endif

static int lo_open(struct block_device *bdev, fmode_t mode)
{
	struct loop_device *lo = bdev->bd_disk->private_data;

	mutex_lock(&lo->lo_ctl_mutex);
	lo->lo_refcnt++;
	mutex_unlock(&lo->lo_ctl_mutex);

	return 0;
}

static int lo_release(struct gendisk *disk, fmode_t mode)
{
	struct loop_device *lo = disk->private_data;

	mutex_lock(&lo->lo_ctl_mutex);

	if (--lo->lo_refcnt)
		goto out;

	if (lo->lo_flags & LO_FLAGS_AUTOCLEAR) {
		/*
		 * In autoclear mode, stop the loop thread
		 * and remove configuration after last close.
		 */
		loop_clr_fd(lo, NULL);
	} else {
		/*
		 * Otherwise keep thread (if running) and config,
		 * but flush possible ongoing bios in thread.
		 */
		loop_flush(lo);
	}

out:
	mutex_unlock(&lo->lo_ctl_mutex);

	return 0;
}

static struct block_device_operations lo_fops = {
	.owner =	THIS_MODULE,
	.open =		lo_open,
	.release =	lo_release,
	.ioctl =	lo_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl =	lo_compat_ioctl,
#endif
};

/*
 * And now the modules code and kernel interface.
 */
static int max_loop;
module_param(max_loop, int, 0);
MODULE_PARM_DESC(max_loop, "Maximum number of loop devices");
module_param(max_part, int, 0);
MODULE_PARM_DESC(max_part, "Maximum number of partitions per loop device");
MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(LOOP_MAJOR);

int loop_register_transfer(struct loop_func_table *funcs)
{
	unsigned int n = funcs->number;

	if (n >= MAX_LO_CRYPT || xfer_funcs[n])
		return -EINVAL;
	xfer_funcs[n] = funcs;
	return 0;
}

int loop_unregister_transfer(int number)
{
	unsigned int n = number;
	struct loop_device *lo;
	struct loop_func_table *xfer;

	if (n == 0 || n >= MAX_LO_CRYPT || (xfer = xfer_funcs[n]) == NULL)
		return -EINVAL;

	xfer_funcs[n] = NULL;

	list_for_each_entry(lo, &loop_devices, lo_list) {
		mutex_lock(&lo->lo_ctl_mutex);

		if (lo->lo_encryption == xfer)
			loop_release_xfer(lo);

		mutex_unlock(&lo->lo_ctl_mutex);
	}

	return 0;
}

EXPORT_SYMBOL(loop_register_transfer);
EXPORT_SYMBOL(loop_unregister_transfer);

static struct loop_device *loop_alloc(int i)
{
	struct loop_device *lo;
	struct gendisk *disk;

	lo = kzalloc(sizeof(*lo), GFP_KERNEL);
	if (!lo)
		goto out;

	lo->lo_queue = blk_alloc_queue(GFP_KERNEL);
	if (!lo->lo_queue)
		goto out_free_dev;

	disk = lo->lo_disk = alloc_disk(1 << part_shift);
	if (!disk)
		goto out_free_queue;

	mutex_init(&lo->lo_ctl_mutex);
	lo->lo_number		= i;
	lo->lo_thread		= NULL;
	init_waitqueue_head(&lo->lo_event);
	init_waitqueue_head(&lo->lo_bio_wait);
	setup_timer(&lo->lo_bio_timer, loop_bio_timer, (unsigned long) lo);
	spin_lock_init(&lo->lo_lock);
	disk->major		= LOOP_MAJOR;
	disk->first_minor	= i << part_shift;
	disk->fops		= &lo_fops;
	disk->private_data	= lo;
	disk->queue		= lo->lo_queue;
	sprintf(disk->disk_name, "loop%d", i);
	return lo;

out_free_queue:
	blk_cleanup_queue(lo->lo_queue);
out_free_dev:
	kfree(lo);
out:
	return NULL;
}

static void loop_free(struct loop_device *lo)
{
	blk_cleanup_queue(lo->lo_queue);
	put_disk(lo->lo_disk);
	list_del(&lo->lo_list);
	kfree(lo);
}

static struct loop_device *loop_init_one(int i)
{
	struct loop_device *lo;

	list_for_each_entry(lo, &loop_devices, lo_list) {
		if (lo->lo_number == i)
			return lo;
	}

	lo = loop_alloc(i);
	if (lo) {
		add_disk(lo->lo_disk);
		list_add_tail(&lo->lo_list, &loop_devices);
	}
	return lo;
}

static void loop_del_one(struct loop_device *lo)
{
	del_gendisk(lo->lo_disk);
	loop_free(lo);
}

static struct kobject *loop_probe(dev_t dev, int *part, void *data)
{
	struct loop_device *lo;
	struct kobject *kobj;

	mutex_lock(&loop_devices_mutex);
	lo = loop_init_one(dev & MINORMASK);
	kobj = lo ? get_disk(lo->lo_disk) : ERR_PTR(-ENOMEM);
	mutex_unlock(&loop_devices_mutex);

	*part = 0;
	return kobj;
}

static int __init loop_init(void)
{
	int i, nr;
	unsigned long range;
	struct loop_device *lo, *next;

	/*
	 * loop module now has a feature to instantiate underlying device
	 * structure on-demand, provided that there is an access dev node.
	 * However, this will not work well with user space tool that doesn't
	 * know about such "feature".  In order to not break any existing
	 * tool, we do the following:
	 *
	 * (1) if max_loop is specified, create that many upfront, and this
	 *     also becomes a hard limit.
	 * (2) if max_loop is not specified, create 8 loop device on module
	 *     load, user can further extend loop device by create dev node
	 *     themselves and have kernel automatically instantiate actual
	 *     device on-demand.
	 */

	part_shift = 0;
	if (max_part > 0)
		part_shift = fls(max_part);

	if (max_loop > 1UL << (MINORBITS - part_shift))
		return -EINVAL;

	if (max_loop) {
		nr = max_loop;
		range = max_loop;
	} else {
		nr = 8;
		range = 1UL << (MINORBITS - part_shift);
	}

	if (register_blkdev(LOOP_MAJOR, "loop"))
		return -EIO;

	for (i = 0; i < nr; i++) {
		lo = loop_alloc(i);
		if (!lo)
			goto Enomem;
		list_add_tail(&lo->lo_list, &loop_devices);
	}

	/* point of no return */

	list_for_each_entry(lo, &loop_devices, lo_list)
		add_disk(lo->lo_disk);

	blk_register_region(MKDEV(LOOP_MAJOR, 0), range,
				  THIS_MODULE, loop_probe, NULL, NULL);

	printk(KERN_INFO "loop: module loaded\n");
	return 0;

Enomem:
	printk(KERN_INFO "loop: out of memory\n");

	list_for_each_entry_safe(lo, next, &loop_devices, lo_list)
		loop_free(lo);

	unregister_blkdev(LOOP_MAJOR, "loop");
	return -ENOMEM;
}

static void __exit loop_exit(void)
{
	unsigned long range;
	struct loop_device *lo, *next;

	range = max_loop ? max_loop :  1UL << (MINORBITS - part_shift);

	list_for_each_entry_safe(lo, next, &loop_devices, lo_list)
		loop_del_one(lo);

	blk_unregister_region(MKDEV(LOOP_MAJOR, 0), range);
	unregister_blkdev(LOOP_MAJOR, "loop");
}

module_init(loop_init);
module_exit(loop_exit);

#ifndef MODULE
static int __init max_loop_setup(char *str)
{
	max_loop = simple_strtol(str, NULL, 0);
	return 1;
}

__setup("max_loop=", max_loop_setup);
#endif
