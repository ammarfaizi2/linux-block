/*
 *	An async IO implementation for Linux
 *	Written by Benjamin LaHaise <bcrl@kvack.org>
 *
 *	Implements an efficient asynchronous io interface.
 *
 *	Copyright 2000, 2001, 2002 Red Hat, Inc.  All Rights Reserved.
 *	Copyright 2018 Christoph Hellwig.
 *
 *	See ../COPYING for licensing terms.
 */
#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/aio_abi.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/backing-dev.h>
#include <linux/refcount.h>
#include <linux/uio.h>

#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_context.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/aio.h>
#include <linux/highmem.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/eventfd.h>
#include <linux/blkdev.h>
#include <linux/compat.h>
#include <linux/migrate.h>
#include <linux/ramfs.h>
#include <linux/percpu-refcount.h>
#include <linux/mount.h>
#include <linux/sizes.h>
#include <linux/nospec.h>
#include <linux/sched/mm.h>

#include <asm/kmap_types.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>

#include "internal.h"

#define KIOCB_KEY		0

#define AIO_RING_MAGIC			0xa10a10a1
#define AIO_RING_COMPAT_FEATURES	1
#define AIO_RING_INCOMPAT_FEATURES	0
struct aio_ring {
	unsigned	id;	/* kernel internal index number */
	unsigned	nr;	/* number of io_events */
	unsigned	head;	/* Written to by userland or under ring_lock
				 * mutex by aio_read_events_ring(). */
	unsigned	tail;

	unsigned	magic;
	unsigned	compat_features;
	unsigned	incompat_features;
	unsigned	header_length;	/* size of aio_ring */


	struct io_event		io_events[0];
}; /* 128 bytes + ring size */

/*
 * Plugging is meant to work with larger batches of IOs. If we don't
 * have more than the below, then don't bother setting up a plug.
 */
#define AIO_PLUG_THRESHOLD	2

#define AIO_IOPOLL_BATCH	8

#define AIO_RING_PAGES	8

struct kioctx_table {
	struct rcu_head		rcu;
	unsigned		nr;
	struct kioctx __rcu	*table[];
};

struct kioctx_cpu {
	unsigned		reqs_available;
};

struct ctx_rq_wait {
	struct completion comp;
	atomic_t count;
};

struct aio_mapped_range {
	struct page **pages;
	long nr_pages;
};

struct aio_iocb_ring {
	struct aio_mapped_range ring_range;	/* maps user SQ ring */
	unsigned int ring_mask;
	bool submit_eagain;

	struct aio_mapped_range iocb_range;	/* maps user iocbs */
};

struct aio_event_ring {
	struct aio_mapped_range ev_range;
	unsigned int ring_mask;
	bool overflow;
};

struct aio_mapped_ubuf {
	u64 ubuf;
	size_t len;
	struct bio_vec *bvec;
	unsigned int nr_bvecs;
};

struct aio_sq_offload {
	struct task_struct *thread;	/* if using a thread */
	struct workqueue_struct *wq;	/* wq offload */
	struct mm_struct *mm;
	struct files_struct *files;
	wait_queue_head_t wait;
};

struct kioctx {
	struct percpu_ref	users;
	atomic_t		dead;

	struct percpu_ref	reqs;

	unsigned long		user_id;

	unsigned int		flags;

	struct __percpu kioctx_cpu *cpu;

	/*
	 * For percpu reqs_available, number of slots we move to/from global
	 * counter at a time:
	 */
	unsigned		req_batch;
	/*
	 * This is what userspace passed to io_setup(), it's not used for
	 * anything but counting against the global max_reqs quota.
	 *
	 * The real limit is nr_events - 1, which will be larger (see
	 * aio_setup_ring())
	 */
	unsigned		max_reqs;

	/* Size of ringbuffer, in units of struct io_event */
	unsigned		nr_events;

	unsigned long		mmap_base;
	unsigned long		mmap_size;

	struct page		**ring_pages;
	long			nr_pages;

	/* if used, fixed mapped user buffers */
	struct aio_mapped_ubuf	*user_bufs;

	/* if used, completion and submission rings */
	struct aio_iocb_ring	sq_ring;
	struct aio_event_ring	cq_ring;

	/* sq ring submitter thread, if used */
	struct aio_sq_offload	sq_offload;

	struct rcu_work		free_rwork;	/* see free_ioctx() */

	/*
	 * signals when all in-flight requests are done
	 */
	struct ctx_rq_wait	*rq_wait;

	struct {
		/*
		 * This counts the number of available slots in the ringbuffer,
		 * so we avoid overflowing it: it's decremented (if positive)
		 * when allocating a kiocb and incremented when the resulting
		 * io_event is pulled off the ringbuffer.
		 *
		 * We batch accesses to it with a percpu version.
		 */
		atomic_t	reqs_available;
	} ____cacheline_aligned_in_smp;

	/* iopoll submission state */
	struct {
		spinlock_t poll_lock;
		struct list_head poll_submitted;
	} ____cacheline_aligned_in_smp;

	/* iopoll completion state */
	struct {
		struct list_head poll_completing;
		struct mutex getevents_lock;
	} ____cacheline_aligned_in_smp;

	struct {
		spinlock_t	ctx_lock;
		struct list_head active_reqs;	/* used for cancellation */
	} ____cacheline_aligned_in_smp;

	struct {
		struct mutex	ring_lock;
		wait_queue_head_t wait;
	} ____cacheline_aligned_in_smp;

	struct {
		unsigned	tail;
		unsigned	completed_events;
		spinlock_t	completion_lock;
	} ____cacheline_aligned_in_smp;

	struct page		*internal_pages[AIO_RING_PAGES];
	struct file		*aio_ring_file;

	unsigned		id;
};

struct fsync_iocb {
	struct work_struct	work;
	struct file		*file;
	bool			datasync;
};

struct poll_iocb {
	struct file		*file;
	struct wait_queue_head	*head;
	__poll_t		events;
	bool			woken;
	bool			cancelled;
	struct wait_queue_entry	wait;
	struct work_struct	work;
};

struct aio_kiocb {
	union {
		struct kiocb		rw;
		struct fsync_iocb	fsync;
		struct poll_iocb	poll;
	};

	struct kioctx		*ki_ctx;
	kiocb_cancel_fn		*ki_cancel;

	union {
		struct iocb __user	*ki_user_iocb;	/* user's aiocb */
		unsigned long		ki_index;
	};

	__u64			ki_user_data;	/* user's data for completion */

	struct list_head	ki_list;	/* the aio core uses this
						 * for cancellation, or for
						 * polled IO */

	unsigned long		ki_flags;
#define KIOCB_F_POLL_COMPLETED	0	/* polled IO has completed */
#define KIOCB_F_POLL_EAGAIN	1	/* polled submission got EAGAIN */
#define KIOCB_F_FORCE_NONBLOCK	2	/* inline submission attempt */

	refcount_t		ki_refcnt;

	union {
		/*
		 * If the aio_resfd field of the userspace iocb is not zero,
		 * this is the underlying eventfd context to deliver events to.
		 */
		struct eventfd_ctx	*ki_eventfd;

		/*
		 * For polled IO, stash completion info here
		 */
		struct io_event		ki_ev;
	};
};

struct aio_submit_state {
	struct kioctx *ctx;

	struct blk_plug plug;
#ifdef CONFIG_BLOCK
	struct blk_plug_cb plug_cb;
#endif

	/*
	 * Polled iocbs that have been submitted, but not added to the ctx yet
	 */
	struct list_head req_list;
	unsigned int req_count;

	/*
	 * aio_kiocb alloc cache
	 */
	void *iocbs[AIO_IOPOLL_BATCH];
	unsigned int free_iocbs;
	unsigned int cur_iocb;

	/*
	 * File reference cache
	 */
	struct file *file;
	unsigned int fd;
	unsigned int has_refs;
	unsigned int used_refs;
	unsigned int ios_left;
};

/*------ sysctl variables----*/
static DEFINE_SPINLOCK(aio_nr_lock);
unsigned long aio_nr;		/* current system wide number of aio requests */
unsigned long aio_max_nr = 0x10000; /* system wide maximum number of aio requests */
/*----end sysctl variables---*/

static struct kmem_cache	*kiocb_cachep;
static struct kmem_cache	*kioctx_cachep;

static struct vfsmount *aio_mnt;

static const struct file_operations aio_ring_fops;
static const struct address_space_operations aio_ctx_aops;

static const unsigned int array_page_shift =
				ilog2(PAGE_SIZE / sizeof(u32));
static const unsigned int iocb_page_shift =
				ilog2(PAGE_SIZE / sizeof(struct iocb));
static const unsigned int ev_page_shift =
				ilog2(PAGE_SIZE / sizeof(struct io_event));

static void aio_iocb_buffer_unmap(struct kioctx *);
static void aio_scqring_unmap(struct kioctx *);
static void aio_iopoll_reap_events(struct kioctx *);
static const struct iocb *aio_iocb_from_index(struct kioctx *ctx, unsigned idx);
static void aio_sqring_unmap_iocb(struct kioctx *ctx, unsigned iocb_index);

static struct file *aio_private_file(struct kioctx *ctx, loff_t nr_pages)
{
	struct file *file;
	struct inode *inode = alloc_anon_inode(aio_mnt->mnt_sb);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	inode->i_mapping->a_ops = &aio_ctx_aops;
	inode->i_mapping->private_data = ctx;
	inode->i_size = PAGE_SIZE * nr_pages;

	file = alloc_file_pseudo(inode, aio_mnt, "[aio]",
				O_RDWR, &aio_ring_fops);
	if (IS_ERR(file))
		iput(inode);
	return file;
}

static struct dentry *aio_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	struct dentry *root = mount_pseudo(fs_type, "aio:", NULL, NULL,
					   AIO_RING_MAGIC);

	if (!IS_ERR(root))
		root->d_sb->s_iflags |= SB_I_NOEXEC;
	return root;
}

/* aio_setup
 *	Creates the slab caches used by the aio routines, panic on
 *	failure as this is done early during the boot sequence.
 */
static int __init aio_setup(void)
{
	static struct file_system_type aio_fs = {
		.name		= "aio",
		.mount		= aio_mount,
		.kill_sb	= kill_anon_super,
	};
	aio_mnt = kern_mount(&aio_fs);
	if (IS_ERR(aio_mnt))
		panic("Failed to create aio fs mount.");

	kiocb_cachep = KMEM_CACHE(aio_kiocb, SLAB_HWCACHE_ALIGN|SLAB_PANIC);
	kioctx_cachep = KMEM_CACHE(kioctx,SLAB_HWCACHE_ALIGN|SLAB_PANIC);
	return 0;
}
__initcall(aio_setup);

static void put_aio_ring_file(struct kioctx *ctx)
{
	struct file *aio_ring_file = ctx->aio_ring_file;
	struct address_space *i_mapping;

	if (aio_ring_file) {
		truncate_setsize(file_inode(aio_ring_file), 0);

		/* Prevent further access to the kioctx from migratepages */
		i_mapping = aio_ring_file->f_mapping;
		spin_lock(&i_mapping->private_lock);
		i_mapping->private_data = NULL;
		ctx->aio_ring_file = NULL;
		spin_unlock(&i_mapping->private_lock);

		fput(aio_ring_file);
	}
}

static void aio_free_ring(struct kioctx *ctx)
{
	int i;

	/* Disconnect the kiotx from the ring file.  This prevents future
	 * accesses to the kioctx from page migration.
	 */
	put_aio_ring_file(ctx);

	for (i = 0; i < ctx->nr_pages; i++) {
		struct page *page;
		pr_debug("pid(%d) [%d] page->count=%d\n", current->pid, i,
				page_count(ctx->ring_pages[i]));
		page = ctx->ring_pages[i];
		if (!page)
			continue;
		ctx->ring_pages[i] = NULL;
		put_page(page);
	}

	if (ctx->ring_pages && ctx->ring_pages != ctx->internal_pages) {
		kfree(ctx->ring_pages);
		ctx->ring_pages = NULL;
	}
}

static int aio_ring_mremap(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct mm_struct *mm = vma->vm_mm;
	struct kioctx_table *table;
	int i, res = -EINVAL;

	spin_lock(&mm->ioctx_lock);
	rcu_read_lock();
	table = rcu_dereference(mm->ioctx_table);
	for (i = 0; i < table->nr; i++) {
		struct kioctx *ctx;

		ctx = rcu_dereference(table->table[i]);
		if (ctx && ctx->aio_ring_file == file) {
			if (!atomic_read(&ctx->dead)) {
				ctx->user_id = ctx->mmap_base = vma->vm_start;
				res = 0;
			}
			break;
		}
	}

	rcu_read_unlock();
	spin_unlock(&mm->ioctx_lock);
	return res;
}

static const struct vm_operations_struct aio_ring_vm_ops = {
	.mremap		= aio_ring_mremap,
#if IS_ENABLED(CONFIG_MMU)
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= filemap_page_mkwrite,
#endif
};

static int aio_ring_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_DONTEXPAND;
	vma->vm_ops = &aio_ring_vm_ops;
	return 0;
}

static const struct file_operations aio_ring_fops = {
	.mmap = aio_ring_mmap,
};

#if IS_ENABLED(CONFIG_MIGRATION)
static int aio_migratepage(struct address_space *mapping, struct page *new,
			struct page *old, enum migrate_mode mode)
{
	struct kioctx *ctx;
	unsigned long flags;
	pgoff_t idx;
	int rc;

	/*
	 * We cannot support the _NO_COPY case here, because copy needs to
	 * happen under the ctx->completion_lock. That does not work with the
	 * migration workflow of MIGRATE_SYNC_NO_COPY.
	 */
	if (mode == MIGRATE_SYNC_NO_COPY)
		return -EINVAL;

	rc = 0;

	/* mapping->private_lock here protects against the kioctx teardown.  */
	spin_lock(&mapping->private_lock);
	ctx = mapping->private_data;
	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	/* The ring_lock mutex.  The prevents aio_read_events() from writing
	 * to the ring's head, and prevents page migration from mucking in
	 * a partially initialized kiotx.
	 */
	if (!mutex_trylock(&ctx->ring_lock)) {
		rc = -EAGAIN;
		goto out;
	}

	idx = old->index;
	if (idx < (pgoff_t)ctx->nr_pages) {
		/* Make sure the old page hasn't already been changed */
		if (ctx->ring_pages[idx] != old)
			rc = -EAGAIN;
	} else
		rc = -EINVAL;

	if (rc != 0)
		goto out_unlock;

	/* Writeback must be complete */
	BUG_ON(PageWriteback(old));
	get_page(new);

	rc = migrate_page_move_mapping(mapping, new, old, mode, 1);
	if (rc != MIGRATEPAGE_SUCCESS) {
		put_page(new);
		goto out_unlock;
	}

	/* Take completion_lock to prevent other writes to the ring buffer
	 * while the old page is copied to the new.  This prevents new
	 * events from being lost.
	 */
	spin_lock_irqsave(&ctx->completion_lock, flags);
	migrate_page_copy(new, old);
	BUG_ON(ctx->ring_pages[idx] != old);
	ctx->ring_pages[idx] = new;
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	/* The old page is no longer accessible. */
	put_page(old);

out_unlock:
	mutex_unlock(&ctx->ring_lock);
out:
	spin_unlock(&mapping->private_lock);
	return rc;
}
#endif

static const struct address_space_operations aio_ctx_aops = {
	.set_page_dirty = __set_page_dirty_no_writeback,
#if IS_ENABLED(CONFIG_MIGRATION)
	.migratepage	= aio_migratepage,
#endif
};

/* Polled IO or SQ/CQ rings don't use the old ring */
static bool aio_ctx_old_ring(struct kioctx *ctx)
{
	return !(ctx->flags & (IOCTX_FLAG_IOPOLL | IOCTX_FLAG_SCQRING));
}

static int aio_setup_ring(struct kioctx *ctx, unsigned int nr_events)
{
	struct aio_ring *ring;
	struct mm_struct *mm = current->mm;
	unsigned long size, unused;
	int nr_pages;
	int i;
	struct file *file;

	/*
	 * Compensate for the ring buffer's head/tail overlap entry.
	 * IO polling doesn't require any io event entries
	 */
	size = sizeof(struct aio_ring);
	if (aio_ctx_old_ring(ctx)) {
		nr_events += 2;	/* 1 is required, 2 for good luck */
		size += sizeof(struct io_event) * nr_events;
	}

	nr_pages = PFN_UP(size);
	if (nr_pages < 0)
		return -EINVAL;

	file = aio_private_file(ctx, nr_pages);
	if (IS_ERR(file)) {
		ctx->aio_ring_file = NULL;
		return -ENOMEM;
	}

	ctx->aio_ring_file = file;
	nr_events = (PAGE_SIZE * nr_pages - sizeof(struct aio_ring))
			/ sizeof(struct io_event);

	ctx->ring_pages = ctx->internal_pages;
	if (nr_pages > AIO_RING_PAGES) {
		ctx->ring_pages = kcalloc(nr_pages, sizeof(struct page *),
					  GFP_KERNEL);
		if (!ctx->ring_pages) {
			put_aio_ring_file(ctx);
			return -ENOMEM;
		}
	}

	for (i = 0; i < nr_pages; i++) {
		struct page *page;
		page = find_or_create_page(file->f_mapping,
					   i, GFP_HIGHUSER | __GFP_ZERO);
		if (!page)
			break;
		pr_debug("pid(%d) page[%d]->count=%d\n",
			 current->pid, i, page_count(page));
		SetPageUptodate(page);
		unlock_page(page);

		ctx->ring_pages[i] = page;
	}
	ctx->nr_pages = i;

	if (unlikely(i != nr_pages)) {
		aio_free_ring(ctx);
		return -ENOMEM;
	}

	ctx->mmap_size = nr_pages * PAGE_SIZE;
	pr_debug("attempting mmap of %lu bytes\n", ctx->mmap_size);

	if (down_write_killable(&mm->mmap_sem)) {
		ctx->mmap_size = 0;
		aio_free_ring(ctx);
		return -EINTR;
	}

	ctx->mmap_base = do_mmap_pgoff(ctx->aio_ring_file, 0, ctx->mmap_size,
				       PROT_READ | PROT_WRITE,
				       MAP_SHARED, 0, &unused, NULL);
	up_write(&mm->mmap_sem);
	if (IS_ERR((void *)ctx->mmap_base)) {
		ctx->mmap_size = 0;
		aio_free_ring(ctx);
		return -ENOMEM;
	}

	pr_debug("mmap address: 0x%08lx\n", ctx->mmap_base);

	ctx->user_id = ctx->mmap_base;
	ctx->nr_events = nr_events; /* trusted copy */

	ring = kmap_atomic(ctx->ring_pages[0]);
	ring->nr = nr_events;	/* user copy */
	ring->id = ~0U;
	ring->head = ring->tail = 0;
	ring->magic = AIO_RING_MAGIC;
	ring->compat_features = AIO_RING_COMPAT_FEATURES;
	ring->incompat_features = AIO_RING_INCOMPAT_FEATURES;
	ring->header_length = sizeof(struct aio_ring);
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	return 0;
}

/*
 * Don't support cancel on anything that isn't old aio
 */
static bool aio_ctx_supports_cancel(struct kioctx *ctx)
{
	return (ctx->flags & (IOCTX_FLAG_IOPOLL | IOCTX_FLAG_SCQRING)) == 0;
}

#define AIO_EVENTS_PER_PAGE	(PAGE_SIZE / sizeof(struct io_event))
#define AIO_EVENTS_FIRST_PAGE	((PAGE_SIZE - sizeof(struct aio_ring)) / sizeof(struct io_event))
#define AIO_EVENTS_OFFSET	(AIO_EVENTS_PER_PAGE - AIO_EVENTS_FIRST_PAGE)

void kiocb_set_cancel_fn(struct kiocb *iocb, kiocb_cancel_fn *cancel)
{
	struct aio_kiocb *req = container_of(iocb, struct aio_kiocb, rw);
	struct kioctx *ctx = req->ki_ctx;
	unsigned long flags;

	if (WARN_ON_ONCE(!aio_ctx_supports_cancel(ctx)))
		return;
	if (WARN_ON_ONCE(!list_empty(&req->ki_list)))
		return;

	spin_lock_irqsave(&ctx->ctx_lock, flags);
	list_add_tail(&req->ki_list, &ctx->active_reqs);
	req->ki_cancel = cancel;
	spin_unlock_irqrestore(&ctx->ctx_lock, flags);
}
EXPORT_SYMBOL(kiocb_set_cancel_fn);

/*
 * free_ioctx() should be RCU delayed to synchronize against the RCU
 * protected lookup_ioctx() and also needs process context to call
 * aio_free_ring().  Use rcu_work.
 */
static void free_ioctx(struct work_struct *work)
{
	struct kioctx *ctx = container_of(to_rcu_work(work), struct kioctx,
					  free_rwork);
	pr_debug("freeing %p\n", ctx);

	aio_scqring_unmap(ctx);
	aio_iocb_buffer_unmap(ctx);
	aio_free_ring(ctx);
	free_percpu(ctx->cpu);
	percpu_ref_exit(&ctx->reqs);
	percpu_ref_exit(&ctx->users);
	kmem_cache_free(kioctx_cachep, ctx);
}

static void free_ioctx_reqs(struct percpu_ref *ref)
{
	struct kioctx *ctx = container_of(ref, struct kioctx, reqs);

	/* At this point we know that there are no any in-flight requests */
	if (ctx->rq_wait && atomic_dec_and_test(&ctx->rq_wait->count))
		complete(&ctx->rq_wait->comp);

	/* Synchronize against RCU protected table->table[] dereferences */
	INIT_RCU_WORK(&ctx->free_rwork, free_ioctx);
	queue_rcu_work(system_wq, &ctx->free_rwork);
}

/*
 * When this function runs, the kioctx has been removed from the "hash table"
 * and ctx->users has dropped to 0, so we know no more kiocbs can be submitted -
 * now it's safe to cancel any that need to be.
 */
static void free_ioctx_users(struct percpu_ref *ref)
{
	struct kioctx *ctx = container_of(ref, struct kioctx, users);
	struct aio_kiocb *req;

	spin_lock_irq(&ctx->ctx_lock);

	while (!list_empty(&ctx->active_reqs)) {
		req = list_first_entry(&ctx->active_reqs,
				       struct aio_kiocb, ki_list);
		req->ki_cancel(&req->rw);
		list_del_init(&req->ki_list);
	}

	spin_unlock_irq(&ctx->ctx_lock);

	percpu_ref_kill(&ctx->reqs);
	percpu_ref_put(&ctx->reqs);
}

static int ioctx_add_table(struct kioctx *ctx, struct mm_struct *mm)
{
	unsigned i, new_nr;
	struct kioctx_table *table, *old;
	struct aio_ring *ring;

	spin_lock(&mm->ioctx_lock);
	table = rcu_dereference_raw(mm->ioctx_table);

	while (1) {
		if (table)
			for (i = 0; i < table->nr; i++)
				if (!rcu_access_pointer(table->table[i])) {
					ctx->id = i;
					rcu_assign_pointer(table->table[i], ctx);
					spin_unlock(&mm->ioctx_lock);

					/* While kioctx setup is in progress,
					 * we are protected from page migration
					 * changes ring_pages by ->ring_lock.
					 */
					ring = kmap_atomic(ctx->ring_pages[0]);
					ring->id = ctx->id;
					kunmap_atomic(ring);
					return 0;
				}

		new_nr = (table ? table->nr : 1) * 4;
		spin_unlock(&mm->ioctx_lock);

		table = kzalloc(sizeof(*table) + sizeof(struct kioctx *) *
				new_nr, GFP_KERNEL);
		if (!table)
			return -ENOMEM;

		table->nr = new_nr;

		spin_lock(&mm->ioctx_lock);
		old = rcu_dereference_raw(mm->ioctx_table);

		if (!old) {
			rcu_assign_pointer(mm->ioctx_table, table);
		} else if (table->nr > old->nr) {
			memcpy(table->table, old->table,
			       old->nr * sizeof(struct kioctx *));

			rcu_assign_pointer(mm->ioctx_table, table);
			kfree_rcu(old, rcu);
		} else {
			kfree(table);
			table = old;
		}
	}
}

static void aio_nr_sub(unsigned nr)
{
	spin_lock(&aio_nr_lock);
	if (WARN_ON(aio_nr - nr > aio_nr))
		aio_nr = 0;
	else
		aio_nr -= nr;
	spin_unlock(&aio_nr_lock);
}

static struct kioctx *io_setup_flags(unsigned long ctxid,
				     unsigned int nr_events, unsigned int flags)
{
	struct mm_struct *mm = current->mm;
	struct kioctx *ctx;
	int err = -ENOMEM;

	/*
	 * Store the original nr_events -- what userspace passed to io_setup(),
	 * for counting against the global limit -- before it changes.
	 */
	unsigned int max_reqs = nr_events;

	if (unlikely(ctxid || nr_events == 0)) {
		pr_debug("EINVAL: ctx %lu nr_events %u\n",
		         ctxid, nr_events);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * We keep track of the number of available ringbuffer slots, to prevent
	 * overflow (reqs_available), and we also use percpu counters for this.
	 *
	 * So since up to half the slots might be on other cpu's percpu counters
	 * and unavailable, double nr_events so userspace sees what they
	 * expected: additionally, we move req_batch slots to/from percpu
	 * counters at a time, so make sure that isn't 0:
	 */
	nr_events = max(nr_events, num_possible_cpus() * 4);
	nr_events *= 2;

	/* Prevent overflows */
	if (nr_events > (0x10000000U / sizeof(struct io_event))) {
		pr_debug("ENOMEM: nr_events too high\n");
		return ERR_PTR(-EINVAL);
	}

	if (!nr_events || (unsigned long)max_reqs > aio_max_nr)
		return ERR_PTR(-EAGAIN);

	ctx = kmem_cache_zalloc(kioctx_cachep, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->flags = flags;
	ctx->max_reqs = max_reqs;

	spin_lock_init(&ctx->ctx_lock);
	spin_lock_init(&ctx->completion_lock);
	mutex_init(&ctx->ring_lock);
	/* Protect against page migration throughout kiotx setup by keeping
	 * the ring_lock mutex held until setup is complete. */
	mutex_lock(&ctx->ring_lock);
	init_waitqueue_head(&ctx->wait);

	INIT_LIST_HEAD(&ctx->active_reqs);

	spin_lock_init(&ctx->poll_lock);
	INIT_LIST_HEAD(&ctx->poll_submitted);
	INIT_LIST_HEAD(&ctx->poll_completing);
	mutex_init(&ctx->getevents_lock);

	if (percpu_ref_init(&ctx->users, free_ioctx_users, 0, GFP_KERNEL))
		goto err;

	if (percpu_ref_init(&ctx->reqs, free_ioctx_reqs, 0, GFP_KERNEL))
		goto err;

	ctx->cpu = alloc_percpu(struct kioctx_cpu);
	if (!ctx->cpu)
		goto err;

	err = aio_setup_ring(ctx, nr_events);
	if (err < 0)
		goto err;

	atomic_set(&ctx->reqs_available, ctx->nr_events - 1);
	ctx->req_batch = (ctx->nr_events - 1) / (num_possible_cpus() * 4);
	if (ctx->req_batch < 1)
		ctx->req_batch = 1;

	/* limit the number of system wide aios */
	spin_lock(&aio_nr_lock);
	if (aio_nr + ctx->max_reqs > aio_max_nr ||
	    aio_nr + ctx->max_reqs < aio_nr) {
		spin_unlock(&aio_nr_lock);
		err = -EAGAIN;
		goto err_ctx;
	}
	aio_nr += ctx->max_reqs;
	spin_unlock(&aio_nr_lock);

	percpu_ref_get(&ctx->users);	/* io_setup() will drop this ref */
	percpu_ref_get(&ctx->reqs);	/* free_ioctx_users() will drop this */

	err = ioctx_add_table(ctx, mm);
	if (err)
		goto err_cleanup;

	/* Release the ring_lock mutex now that all setup is complete. */
	mutex_unlock(&ctx->ring_lock);

	pr_debug("allocated ioctx %p[%ld]: mm=%p mask=0x%x\n",
		 ctx, ctx->user_id, mm, ctx->nr_events);
	return ctx;

err_cleanup:
	aio_nr_sub(ctx->max_reqs);
err_ctx:
	atomic_set(&ctx->dead, 1);
	if (ctx->mmap_size)
		vm_munmap(ctx->mmap_base, ctx->mmap_size);
	aio_free_ring(ctx);
err:
	mutex_unlock(&ctx->ring_lock);
	free_percpu(ctx->cpu);
	percpu_ref_exit(&ctx->reqs);
	percpu_ref_exit(&ctx->users);
	kmem_cache_free(kioctx_cachep, ctx);
	pr_debug("error allocating ioctx %d\n", err);
	return ERR_PTR(err);
}

/* kill_ioctx
 *	Cancels all outstanding aio requests on an aio context.  Used
 *	when the processes owning a context have all exited to encourage
 *	the rapid destruction of the kioctx.
 */
static int kill_ioctx(struct mm_struct *mm, struct kioctx *ctx,
		      struct ctx_rq_wait *wait)
{
	struct kioctx_table *table;

	mutex_lock(&ctx->getevents_lock);
	spin_lock(&mm->ioctx_lock);
	if (atomic_xchg(&ctx->dead, 1)) {
		spin_unlock(&mm->ioctx_lock);
		mutex_unlock(&ctx->getevents_lock);
		return -EINVAL;
	}
	aio_iopoll_reap_events(ctx);
	mutex_unlock(&ctx->getevents_lock);

	table = rcu_dereference_raw(mm->ioctx_table);
	WARN_ON(ctx != rcu_access_pointer(table->table[ctx->id]));
	RCU_INIT_POINTER(table->table[ctx->id], NULL);
	spin_unlock(&mm->ioctx_lock);

	/* free_ioctx_reqs() will do the necessary RCU synchronization */
	wake_up_all(&ctx->wait);

	/*
	 * It'd be more correct to do this in free_ioctx(), after all
	 * the outstanding kiocbs have finished - but by then io_destroy
	 * has already returned, so io_setup() could potentially return
	 * -EAGAIN with no ioctxs actually in use (as far as userspace
	 *  could tell).
	 */
	aio_nr_sub(ctx->max_reqs);

	if (ctx->mmap_size)
		vm_munmap(ctx->mmap_base, ctx->mmap_size);

	ctx->rq_wait = wait;
	percpu_ref_kill(&ctx->users);
	return 0;
}

/*
 * exit_aio: called when the last user of mm goes away.  At this point, there is
 * no way for any new requests to be submited or any of the io_* syscalls to be
 * called on the context.
 *
 * There may be outstanding kiocbs, but free_ioctx() will explicitly wait on
 * them.
 */
void exit_aio(struct mm_struct *mm)
{
	struct kioctx_table *table = rcu_dereference_raw(mm->ioctx_table);
	struct ctx_rq_wait wait;
	int i, skipped;

	if (!table)
		return;

	atomic_set(&wait.count, table->nr);
	init_completion(&wait.comp);

	skipped = 0;
	for (i = 0; i < table->nr; ++i) {
		struct kioctx *ctx =
			rcu_dereference_protected(table->table[i], true);

		if (!ctx) {
			skipped++;
			continue;
		}

		/*
		 * We don't need to bother with munmap() here - exit_mmap(mm)
		 * is coming and it'll unmap everything. And we simply can't,
		 * this is not necessarily our ->mm.
		 * Since kill_ioctx() uses non-zero ->mmap_size as indicator
		 * that it needs to unmap the area, just set it to 0.
		 */
		ctx->mmap_size = 0;
		kill_ioctx(mm, ctx, &wait);
	}

	if (!atomic_sub_and_test(skipped, &wait.count)) {
		/* Wait until all IO for the context are done. */
		wait_for_completion(&wait.comp);
	}

	RCU_INIT_POINTER(mm->ioctx_table, NULL);
	kfree(table);
}

static void put_reqs_available(struct kioctx *ctx, unsigned nr)
{
	struct kioctx_cpu *kcpu;
	unsigned long flags;

	local_irq_save(flags);
	kcpu = this_cpu_ptr(ctx->cpu);
	kcpu->reqs_available += nr;

	while (kcpu->reqs_available >= ctx->req_batch * 2) {
		kcpu->reqs_available -= ctx->req_batch;
		atomic_add(ctx->req_batch, &ctx->reqs_available);
	}

	local_irq_restore(flags);
}

static bool __get_reqs_available(struct kioctx *ctx)
{
	struct kioctx_cpu *kcpu;
	bool ret = false;
	unsigned long flags;

	local_irq_save(flags);
	kcpu = this_cpu_ptr(ctx->cpu);
	if (!kcpu->reqs_available) {
		int old, avail = atomic_read(&ctx->reqs_available);

		do {
			if (avail < ctx->req_batch)
				goto out;

			old = avail;
			avail = atomic_cmpxchg(&ctx->reqs_available,
					       avail, avail - ctx->req_batch);
		} while (avail != old);

		kcpu->reqs_available += ctx->req_batch;
	}

	ret = true;
	kcpu->reqs_available--;
out:
	local_irq_restore(flags);
	return ret;
}

/* refill_reqs_available
 *	Updates the reqs_available reference counts used for tracking the
 *	number of free slots in the completion ring.  This can be called
 *	from aio_complete() (to optimistically update reqs_available) or
 *	from aio_get_req() (the we're out of events case).  It must be
 *	called holding ctx->completion_lock.
 */
static void refill_reqs_available(struct kioctx *ctx, unsigned head,
                                  unsigned tail)
{
	unsigned events_in_ring, completed;

	/* Clamp head since userland can write to it. */
	head %= ctx->nr_events;
	if (head <= tail)
		events_in_ring = tail - head;
	else
		events_in_ring = ctx->nr_events - (head - tail);

	completed = ctx->completed_events;
	if (events_in_ring < completed)
		completed -= events_in_ring;
	else
		completed = 0;

	if (!completed)
		return;

	ctx->completed_events -= completed;
	put_reqs_available(ctx, completed);
}

/* user_refill_reqs_available
 *	Called to refill reqs_available when aio_get_req() encounters an
 *	out of space in the completion ring.
 */
static void user_refill_reqs_available(struct kioctx *ctx)
{
	spin_lock_irq(&ctx->completion_lock);
	if (ctx->completed_events) {
		struct aio_ring *ring;
		unsigned head;

		/* Access of ring->head may race with aio_read_events_ring()
		 * here, but that's okay since whether we read the old version
		 * or the new version, and either will be valid.  The important
		 * part is that head cannot pass tail since we prevent
		 * aio_complete() from updating tail by holding
		 * ctx->completion_lock.  Even if head is invalid, the check
		 * against ctx->completed_events below will make sure we do the
		 * safe/right thing.
		 */
		ring = kmap_atomic(ctx->ring_pages[0]);
		head = ring->head;
		kunmap_atomic(ring);

		refill_reqs_available(ctx, head, ctx->tail);
	}

	spin_unlock_irq(&ctx->completion_lock);
}

static bool get_reqs_available(struct kioctx *ctx)
{
	if (__get_reqs_available(ctx))
		return true;
	user_refill_reqs_available(ctx);
	return __get_reqs_available(ctx);
}

static void aio_iocb_init(struct kioctx *ctx, struct aio_kiocb *req)
{
	percpu_ref_get(&ctx->reqs);
	req->ki_ctx = ctx;
	INIT_LIST_HEAD(&req->ki_list);
	req->ki_flags = 0;
	refcount_set(&req->ki_refcnt, 0);
	req->ki_eventfd = NULL;
}

/* aio_get_req
 *	Allocate a slot for an aio request.
 * Returns NULL if no requests are free.
 */
static struct aio_kiocb *aio_get_req(struct kioctx *ctx,
				     struct aio_submit_state *state)
{
	struct aio_kiocb *req;

	if (!state)
		req = kmem_cache_alloc(kiocb_cachep, GFP_KERNEL);
	else if (!state->free_iocbs) {
		size_t size;
		int ret;

		size = min_t(size_t, state->ios_left, ARRAY_SIZE(state->iocbs));
		ret = kmem_cache_alloc_bulk(kiocb_cachep, GFP_KERNEL, size,
						state->iocbs);
		if (ret <= 0)
			return ERR_PTR(-ENOMEM);
		state->free_iocbs = ret - 1;
		state->cur_iocb = 1;
		req = state->iocbs[0];
	} else {
		req = state->iocbs[state->cur_iocb];
		state->free_iocbs--;
		state->cur_iocb++;
	}

	if (req)
		aio_iocb_init(ctx, req);

	return req;
}

static struct kioctx *lookup_ioctx(unsigned long ctx_id)
{
	struct aio_ring __user *ring  = (void __user *)ctx_id;
	struct mm_struct *mm = current->mm;
	struct kioctx *ctx, *ret = NULL;
	struct kioctx_table *table;
	unsigned id;

	if (get_user(id, &ring->id))
		return NULL;

	rcu_read_lock();
	table = rcu_dereference(mm->ioctx_table);

	if (!table || id >= table->nr)
		goto out;

	id = array_index_nospec(id, table->nr);
	ctx = rcu_dereference(table->table[id]);
	if (ctx && ctx->user_id == ctx_id) {
		if (percpu_ref_tryget_live(&ctx->users))
			ret = ctx;
	}
out:
	rcu_read_unlock();
	return ret;
}

static inline void iocb_put(struct aio_kiocb *iocb)
{
	if (refcount_read(&iocb->ki_refcnt) == 0 ||
	    refcount_dec_and_test(&iocb->ki_refcnt)) {
		percpu_ref_put(&iocb->ki_ctx->reqs);
		kmem_cache_free(kiocb_cachep, iocb);
	}
}

static void iocb_put_many(struct kioctx *ctx, void **iocbs, int *nr)
{
	if (*nr) {
		percpu_ref_put_many(&ctx->reqs, *nr);
		kmem_cache_free_bulk(kiocb_cachep, *nr, iocbs);
		*nr = 0;
	}
}

static void aio_fill_event(struct io_event *ev, struct aio_kiocb *iocb,
			   long res, long res2)
{
	ev->obj = iocb->ki_index;
	ev->data = iocb->ki_user_data;
	ev->res = res;
	ev->res2 = res2;
}

static struct aio_sq_ring *aio_get_sqring(struct kioctx *ctx)
{
	return kmap_atomic(ctx->sq_ring.ring_range.pages[0]);
}

static void aio_put_sqring(struct kioctx *ctx, struct aio_sq_ring *ring,
			   bool flush)
{
	kunmap_atomic(ring);
	if (flush)
		flush_dcache_page(ctx->sq_ring.ring_range.pages[0]);
}

static void aio_put_cqring(struct kioctx *ctx, struct aio_cq_ring *ring,
			   bool flush)
{
	kunmap_atomic(ring);
	if (flush)
		flush_dcache_page(ctx->cq_ring.ev_range.pages[0]);
}

static struct aio_cq_ring *aio_get_cqring(struct kioctx *ctx)
{
	return kmap_atomic(ctx->cq_ring.ev_range.pages[0]);
}

static void aio_commit_cqring(struct kioctx *ctx, struct io_event *ev)
{
	struct aio_cq_ring *ring = aio_get_cqring(ctx);
	unsigned prev_index;
	struct page *page;

	prev_index = ring->tail++;
	smp_wmb();
	aio_put_cqring(ctx, ring, true);

	prev_index &= ctx->cq_ring.ring_mask;
	prev_index += offsetof(struct aio_cq_ring, events) >> 5;

	page = ctx->cq_ring.ev_range.pages[prev_index >> ev_page_shift];
	prev_index &= ((1 << ev_page_shift) - 1);
	kunmap_atomic(ev - prev_index);
	flush_dcache_page(page);
}

static struct io_event *aio_peek_cqring(struct kioctx *ctx)
{
	struct aio_cq_ring *ring = aio_get_cqring(ctx);
	struct io_event *ev;
	unsigned tail;

	smp_rmb();
	tail = READ_ONCE(ring->tail);
	if (tail + 1 == READ_ONCE(ring->head)) {
		aio_put_cqring(ctx, ring, false);
		return NULL;
	}
	aio_put_cqring(ctx, ring, false);

	tail &= ctx->cq_ring.ring_mask;
	tail += offsetof(struct aio_cq_ring, events) >> 5;
	ev = kmap_atomic(ctx->cq_ring.ev_range.pages[tail >> ev_page_shift]);
	tail &= ((1 << ev_page_shift) - 1);
	return ev + tail;
}

static void aio_ring_complete(struct kioctx *ctx, struct aio_kiocb *iocb,
			      long res, long res2)
{
	struct aio_ring	*ring;
	struct io_event	*ev_page, *event;
	unsigned tail, pos, head;
	unsigned long	flags;

	/*
	 * Add a completion event to the ring buffer. Must be done holding
	 * ctx->completion_lock to prevent other code from messing with the tail
	 * pointer since we might be called from irq context.
	 */
	spin_lock_irqsave(&ctx->completion_lock, flags);

	tail = ctx->tail;
	pos = tail + AIO_EVENTS_OFFSET;

	if (++tail >= ctx->nr_events)
		tail = 0;

	ev_page = kmap_atomic(ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE]);
	event = ev_page + pos % AIO_EVENTS_PER_PAGE;

	aio_fill_event(event, iocb, res, res2);

	kunmap_atomic(ev_page);
	flush_dcache_page(ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE]);

	pr_debug("%p[%u]: %p: %p %Lx %lx %lx\n",
		 ctx, tail, iocb, iocb->ki_user_iocb, iocb->ki_user_data,
		 res, res2);

	/* after flagging the request as done, we
	 * must never even look at it again
	 */
	smp_wmb();	/* make event visible before updating tail */

	ctx->tail = tail;

	ring = kmap_atomic(ctx->ring_pages[0]);
	head = ring->head;
	ring->tail = tail;
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	ctx->completed_events++;
	if (ctx->completed_events > 1)
		refill_reqs_available(ctx, head, tail);
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	pr_debug("added to ring %p at [%u]\n", iocb, tail);
}

/* aio_complete
 *	Called when the io request on the given iocb is complete.
 */
static void aio_complete(struct aio_kiocb *iocb, long res, long res2)
{
	struct kioctx *ctx = iocb->ki_ctx;

	if (ctx->flags & IOCTX_FLAG_SCQRING) {
		unsigned long flags;
		struct io_event *ev;

		/*
		 * Catch EAGAIN early if we've forced a nonblock attempt, as
		 * we don't want to pass that back down to userspace through
		 * the CQ ring. Just mark the ctx as such, so the caller will
		 * see it and punt to workqueue. This is just for buffered
		 * aio reads.
		 */
		if (res == -EAGAIN &&
		    test_bit(KIOCB_F_FORCE_NONBLOCK, &iocb->ki_flags)) {
			ctx->sq_ring.submit_eagain = true;
		} else {
			/*
			 * If we can't get a cq entry, userspace overflowed the
			 * submission (by quite a lot). Flag it as an overflow
			 * condition, and next io_ring_enter(2) call will return
			 * -EOVERFLOW.
			 */
			spin_lock_irqsave(&ctx->completion_lock, flags);
			ev = aio_peek_cqring(ctx);
			if (ev) {
				aio_fill_event(ev, iocb, res, res2);
				aio_commit_cqring(ctx, ev);
			} else
				ctx->cq_ring.overflow = true;
			spin_unlock_irqrestore(&ctx->completion_lock, flags);
		}
	} else {
		aio_ring_complete(ctx, iocb, res, res2);

		/*
		 * We have to order our ring_info tail store above and test
		 * of the wait list below outside the wait lock.  This is
		 * like in wake_up_bit() where clearing a bit has to be
		 * ordered with the unlocked test.
		 */
		smp_mb();
	}

	/*
	 * Check if the user asked us to deliver the result through an
	 * eventfd. The eventfd_signal() function is safe to be called
	 * from IRQ context.
	 */
	if (iocb->ki_eventfd) {
		eventfd_signal(iocb->ki_eventfd, 1);
		eventfd_ctx_put(iocb->ki_eventfd);
	}

	if (waitqueue_active(&ctx->wait))
		wake_up(&ctx->wait);
	iocb_put(iocb);
}

/* aio_read_events_ring
 *	Pull an event off of the ioctx's event ring.  Returns the number of
 *	events fetched
 */
static long aio_read_events_ring(struct kioctx *ctx,
				 struct io_event __user *event, long nr)
{
	struct aio_ring *ring;
	unsigned head, tail, pos;
	long ret = 0;
	int copy_ret;

	/*
	 * The mutex can block and wake us up and that will cause
	 * wait_event_interruptible_hrtimeout() to schedule without sleeping
	 * and repeat. This should be rare enough that it doesn't cause
	 * peformance issues. See the comment in read_events() for more detail.
	 */
	sched_annotate_sleep();
	mutex_lock(&ctx->ring_lock);

	/* Access to ->ring_pages here is protected by ctx->ring_lock. */
	ring = kmap_atomic(ctx->ring_pages[0]);
	head = ring->head;
	tail = ring->tail;
	kunmap_atomic(ring);

	/*
	 * Ensure that once we've read the current tail pointer, that
	 * we also see the events that were stored up to the tail.
	 */
	smp_rmb();

	pr_debug("h%u t%u m%u\n", head, tail, ctx->nr_events);

	if (head == tail)
		goto out;

	head %= ctx->nr_events;
	tail %= ctx->nr_events;

	while (ret < nr) {
		long avail;
		struct io_event *ev;
		struct page *page;

		avail = (head <= tail ?  tail : ctx->nr_events) - head;
		if (head == tail)
			break;

		pos = head + AIO_EVENTS_OFFSET;
		page = ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE];
		pos %= AIO_EVENTS_PER_PAGE;

		avail = min(avail, nr - ret);
		avail = min_t(long, avail, AIO_EVENTS_PER_PAGE - pos);

		ev = kmap(page);
		copy_ret = copy_to_user(event + ret, ev + pos,
					sizeof(*ev) * avail);
		kunmap(page);

		if (unlikely(copy_ret)) {
			ret = -EFAULT;
			goto out;
		}

		ret += avail;
		head += avail;
		head %= ctx->nr_events;
	}

	ring = kmap_atomic(ctx->ring_pages[0]);
	ring->head = head;
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	pr_debug("%li  h%u t%u\n", ret, head, tail);
out:
	mutex_unlock(&ctx->ring_lock);

	return ret;
}

static bool aio_read_events(struct kioctx *ctx, long min_nr, long nr,
			    struct io_event __user *event, long *i)
{
	long ret = aio_read_events_ring(ctx, event + *i, nr - *i);

	if (ret > 0)
		*i += ret;

	if (unlikely(atomic_read(&ctx->dead)))
		ret = -EINVAL;

	if (!*i)
		*i = ret;

	return ret < 0 || *i >= min_nr;
}

/*
 * Process completed iocb iopoll entries, copying the result to userspace.
 */
static long aio_iopoll_reap(struct kioctx *ctx, struct io_event __user *evs,
			    unsigned int *nr_events, long max)
{
	void *iocbs[AIO_IOPOLL_BATCH];
	struct aio_kiocb *iocb, *n;
	int file_count, to_free = 0, ret = 0;
	struct file *file = NULL;

	/* Shouldn't happen... */
	if (*nr_events >= max)
		return 0;

	list_for_each_entry_safe(iocb, n, &ctx->poll_completing, ki_list) {
		struct io_event *ev = NULL;

		if (*nr_events == max)
			break;
		if (!test_bit(KIOCB_F_POLL_COMPLETED, &iocb->ki_flags))
			continue;
		if (to_free == AIO_IOPOLL_BATCH)
			iocb_put_many(ctx, iocbs, &to_free);

		/* Will only happen if the application over-commits */
		ret = -EAGAIN;
		if (ctx->flags & IOCTX_FLAG_SCQRING) {
			ev = aio_peek_cqring(ctx);
			if (!ev)
				break;
		}

		list_del(&iocb->ki_list);
		iocbs[to_free++] = iocb;

		/*
		 * Batched puts of the same file, to avoid dirtying the
		 * file usage count multiple times, if avoidable.
		 */
		if (!file) {
			file = iocb->rw.ki_filp;
			file_count = 1;
		} else if (file == iocb->rw.ki_filp) {
			file_count++;
		} else {
			fput_many(file, file_count);
			file = iocb->rw.ki_filp;
			file_count = 1;
		}

		if (ev) {
			memcpy(ev, &iocb->ki_ev, sizeof(*ev));
			aio_commit_cqring(ctx, ev);
		} else if (evs && copy_to_user(evs + *nr_events, &iocb->ki_ev,
				sizeof(iocb->ki_ev))) {
			ret = -EFAULT;
			break;
		}
		(*nr_events)++;
	}

	if (file)
		fput_many(file, file_count);

	if (to_free)
		iocb_put_many(ctx, iocbs, &to_free);

	return ret;
}

/*
 * Poll for a mininum of 'min' events, and a maximum of 'max'. Note that if
 * min == 0 we consider that a non-spinning poll check - we'll still enter
 * the driver poll loop, but only as a non-spinning completion check.
 */
static int aio_iopoll_getevents(struct kioctx *ctx,
				struct io_event __user *event,
				unsigned int *nr_events, long min, long max)
{
	struct aio_kiocb *iocb;
	int to_poll, polled, ret;

	/*
	 * Check if we already have done events that satisfy what we need
	 */
	if (!list_empty(&ctx->poll_completing)) {
		ret = aio_iopoll_reap(ctx, event, nr_events, max);
		if (ret < 0)
			return ret;
		if ((min && *nr_events >= min) || *nr_events >= max)
			return 0;
	}

	/*
	 * Take in a new working set from the submitted list, if possible.
	 */
	if (!list_empty_careful(&ctx->poll_submitted)) {
		spin_lock(&ctx->poll_lock);
		list_splice_init(&ctx->poll_submitted, &ctx->poll_completing);
		spin_unlock(&ctx->poll_lock);
	}

	if (list_empty(&ctx->poll_completing))
		return 0;

	/*
	 * Check again now that we have a new batch.
	 */
	ret = aio_iopoll_reap(ctx, event, nr_events, max);
	if (ret < 0)
		return ret;
	if ((min && *nr_events >= min) || *nr_events >= max)
		return 0;

	/*
	 * Find up to 'max' worth of events to poll for, including the
	 * events we already successfully polled
	 */
	polled = to_poll = 0;
	list_for_each_entry(iocb, &ctx->poll_completing, ki_list) {
		/*
		 * Poll for needed events with spin == true, anything after
		 * that we just check if we have more, up to max.
		 */
		bool spin = !polled || *nr_events < min;
		struct kiocb *kiocb = &iocb->rw;

		if (test_bit(KIOCB_F_POLL_COMPLETED, &iocb->ki_flags))
			break;
		if (++to_poll + *nr_events > max)
			break;

		ret = kiocb->ki_filp->f_op->iopoll(kiocb, spin);
		if (ret < 0)
			return ret;

		polled += ret;
		if (polled + *nr_events >= max)
			break;
	}

	ret = aio_iopoll_reap(ctx, event, nr_events, max);
	if (ret < 0)
		return ret;
	if (*nr_events >= min)
		return 0;
	return to_poll;
}

/*
 * We can't just wait for polled events to come to us, we have to actively
 * find and complete them.
 */
static void aio_iopoll_reap_events(struct kioctx *ctx)
{
	if (!(ctx->flags & IOCTX_FLAG_IOPOLL))
		return;

	while (!list_empty_careful(&ctx->poll_submitted) ||
	       !list_empty(&ctx->poll_completing)) {
		unsigned int nr_events = 0;

		aio_iopoll_getevents(ctx, NULL, &nr_events, 1, UINT_MAX);
	}
}

static int __aio_iopoll_check(struct kioctx *ctx, struct io_event __user *event,
			      unsigned int *nr_events, long min_nr, long max_nr)
{
	int ret = 0;

	while (!*nr_events || !need_resched()) {
		int tmin = 0;

		if (*nr_events < min_nr)
			tmin = min_nr - *nr_events;

		ret = aio_iopoll_getevents(ctx, event, nr_events, tmin, max_nr);
		if (ret <= 0)
			break;
		ret = 0;
	}

	return ret;
}

static int aio_iopoll_check(struct kioctx *ctx, long min_nr, long nr,
			    struct io_event __user *event)
{
	unsigned int nr_events = 0;
	int ret;

	/* Only allow one thread polling at a time */
	if (!mutex_trylock(&ctx->getevents_lock))
		return -EBUSY;
	if (unlikely(atomic_read(&ctx->dead))) {
		ret = -EINVAL;
		goto err;
	}

	ret = __aio_iopoll_check(ctx, event, &nr_events, min_nr, nr);
err:
	mutex_unlock(&ctx->getevents_lock);
	return nr_events ? nr_events : ret;
}

static long read_events(struct kioctx *ctx, long min_nr, long nr,
			struct io_event __user *event,
			ktime_t until)
{
	long ret = 0;

	/*
	 * Note that aio_read_events() is being called as the conditional - i.e.
	 * we're calling it after prepare_to_wait() has set task state to
	 * TASK_INTERRUPTIBLE.
	 *
	 * But aio_read_events() can block, and if it blocks it's going to flip
	 * the task state back to TASK_RUNNING.
	 *
	 * This should be ok, provided it doesn't flip the state back to
	 * TASK_RUNNING and return 0 too much - that causes us to spin. That
	 * will only happen if the mutex_lock() call blocks, and we then find
	 * the ringbuffer empty. So in practice we should be ok, but it's
	 * something to be aware of when touching this code.
	 */
	if (until == 0)
		aio_read_events(ctx, min_nr, nr, event, &ret);
	else
		wait_event_interruptible_hrtimeout(ctx->wait,
				aio_read_events(ctx, min_nr, nr, event, &ret),
				until);
	return ret;
}

static int aio_sq_thread(void *);

static int aio_sq_thread_start(struct kioctx *ctx)
{
	struct aio_sq_offload *aso = &ctx->sq_offload;
	int ret;

	memset(aso, 0, sizeof(*aso));
	init_waitqueue_head(&aso->wait);

	if (!(ctx->flags & IOCTX_FLAG_FIXEDBUFS))
		aso->mm = current->mm;

	ret = -EBADF;
	aso->files = get_files_struct(current);
	if (!aso->files)
		goto err;

	if (ctx->flags & IOCTX_FLAG_SQTHREAD) {
		struct aio_sq_ring *ring;
		char name[32];
		int cpu;

		ring = aio_get_sqring(ctx);
		cpu = ring->sq_thread_cpu;
		aio_put_sqring(ctx, ring, false);

		snprintf(name, sizeof(name), "aio-sq-%lu/%d", ctx->user_id,
					cpu);
		aso->thread = kthread_create_on_cpu(aio_sq_thread, ctx, cpu,
							name);
		if (IS_ERR(aso->thread)) {
			ret = PTR_ERR(aso->thread);
			aso->thread = NULL;
			goto err;
		}
		wake_up_process(aso->thread);
	} else if (ctx->flags & IOCTX_FLAG_SQWQ) {
		struct aio_sq_ring *ring;
		int concurrency;

		/* Do QD, or 2 * CPUS, whatever is smallest */
		ring = aio_get_sqring(ctx);
		concurrency = min(ring->nr_events - 1, 2 * num_online_cpus());
		aio_put_sqring(ctx, ring, false);

		aso->wq = alloc_workqueue("aio-sq-%lu",
						WQ_UNBOUND | WQ_FREEZABLE,
						concurrency, ctx->user_id);
		if (!aso->wq) {
			ret = -ENOMEM;
			goto err;
		}
	}

	return 0;
err:
	if (aso->files) {
		put_files_struct(aso->files);
		aso->files = NULL;
	}
	if (aso->mm)
		aso->mm = NULL;
	return ret;
}

static void aio_unmap_range(struct aio_mapped_range *range)
{
	int i;

	if (!range->nr_pages)
		return;

	for (i = 0; i < range->nr_pages; i++)
		put_page(range->pages[i]);

	kfree(range->pages);
	range->pages = NULL;
	range->nr_pages = 0;
}

static int aio_map_range(struct aio_mapped_range *range, void __user *uaddr,
			 size_t size, int gup_flags)
{
	int nr_pages, ret;

	if ((unsigned long) uaddr & ~PAGE_MASK)
		return -EINVAL;

	nr_pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	range->pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!range->pages)
		return -ENOMEM;

	down_write(&current->mm->mmap_sem);
	ret = get_user_pages((unsigned long) uaddr, nr_pages, gup_flags,
				range->pages, NULL);
	up_write(&current->mm->mmap_sem);

	if (ret < nr_pages) {
		kfree(range->pages);
		return -ENOMEM;
	}

	range->nr_pages = nr_pages;
	return 0;
}

static void aio_scqring_unmap(struct kioctx *ctx)
{
	struct aio_sq_offload *aso = &ctx->sq_offload;

	if (aso->thread) {
		kthread_park(aso->thread);
		kthread_stop(aso->thread);
		aso->thread = NULL;
	} else if (aso->wq) {
		destroy_workqueue(aso->wq);
		aso->wq = NULL;
	}
	if (aso->files) {
		put_files_struct(aso->files);
		aso->files = NULL;
	}
	aio_unmap_range(&ctx->sq_ring.ring_range);
	aio_unmap_range(&ctx->sq_ring.iocb_range);
	aio_unmap_range(&ctx->cq_ring.ev_range);
}

static int aio_scqring_map(struct kioctx *ctx,
			   struct aio_sq_ring __user *usq_ring,
			   struct aio_cq_ring __user *ucq_ring)
{
	int ret, sq_ring_size, cq_ring_size;
	struct aio_sq_ring *sq_ring;
	struct aio_cq_ring *cq_ring;
	void __user *uptr;
	size_t size;

	/* SQ/CQ ring has to be a power-of-2 */
	if (!is_power_of_2(ctx->max_reqs))
		return -EINVAL;

	/*
	 * The CQ ring size is twice the size of the SQ ring. The iocbs in
	 * the SQ ring are only used for submission, so this allows the app
	 * some flexibility in overcommitting a bit without running into a
	 * CQ ring shortage.
	 */
	sq_ring_size = ctx->max_reqs;
	cq_ring_size = 2 * ctx->max_reqs;

	/* Map SQ ring and iocbs */
	size = sizeof(struct aio_sq_ring) + sq_ring_size * sizeof(u32);
	ret = aio_map_range(&ctx->sq_ring.ring_range, usq_ring, size,
				FOLL_WRITE);
	if (ret)
		return ret;

	sq_ring = aio_get_sqring(ctx);
	if (sq_ring->nr_events != sq_ring_size) {
		aio_put_sqring(ctx, sq_ring, false);
		ret = -EFAULT;
		goto err;
	}
	sq_ring->head = sq_ring->tail = 0;
	ctx->sq_ring.ring_mask = sq_ring_size - 1;

	size = sizeof(struct iocb) * sq_ring_size;
	uptr = (void __user *) (unsigned long) sq_ring->iocbs;
	aio_put_sqring(ctx, sq_ring, true);

	ret = aio_map_range(&ctx->sq_ring.iocb_range, uptr, size, 0);
	if (ret)
		goto err;

	/* Map CQ ring and io_events */
	size = sizeof(struct aio_cq_ring) +
			cq_ring_size * sizeof(struct io_event);
	ret = aio_map_range(&ctx->cq_ring.ev_range, ucq_ring, size, FOLL_WRITE);
	if (ret)
		goto err;

	cq_ring = aio_get_cqring(ctx);
	if (cq_ring->nr_events != cq_ring_size) {
		aio_put_cqring(ctx, cq_ring, false);
		ret = -EFAULT;
		goto err;
	}
	cq_ring->head = cq_ring->tail = 0;
	aio_put_cqring(ctx, cq_ring, true);
	ctx->cq_ring.ring_mask = cq_ring_size - 1;

	if (ctx->flags & (IOCTX_FLAG_SQTHREAD | IOCTX_FLAG_SQWQ))
		ret = aio_sq_thread_start(ctx);

err:
	if (ret) {
		aio_unmap_range(&ctx->sq_ring.ring_range);
		aio_unmap_range(&ctx->sq_ring.iocb_range);
		aio_unmap_range(&ctx->cq_ring.ev_range);
	}
	return ret;
}

static void aio_iocb_buffer_unmap(struct kioctx *ctx)
{
	int i, j;

	if (!ctx->user_bufs)
		return;

	for (i = 0; i < ctx->max_reqs; i++) {
		struct aio_mapped_ubuf *amu = &ctx->user_bufs[i];

		for (j = 0; j < amu->nr_bvecs; j++)
			put_page(amu->bvec[j].bv_page);

		kfree(amu->bvec);
		amu->nr_bvecs = 0;
	}

	kfree(ctx->user_bufs);
	ctx->user_bufs = NULL;
}

static int aio_iocb_buffer_map(struct kioctx *ctx)
{
	unsigned long total_pages, page_limit;
	struct page **pages = NULL;
	int i, j, got_pages = 0;
	const struct iocb *iocb;
	int ret = -EINVAL;

	ctx->user_bufs = kcalloc(ctx->max_reqs, sizeof(struct aio_mapped_ubuf),
					GFP_KERNEL);
	if (!ctx->user_bufs)
		return -ENOMEM;

	/* Don't allow more pages than we can safely lock */
	total_pages = 0;
	page_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	for (i = 0; i < ctx->max_reqs; i++) {
		struct aio_mapped_ubuf *amu = &ctx->user_bufs[i];
		unsigned long off, start, end, ubuf;
		int pret, nr_pages;
		size_t size;

		iocb = aio_iocb_from_index(ctx, i);

		/*
		 * Don't impose further limits on the size and buffer
		 * constraints here, we'll -EINVAL later when IO is
		 * submitted if they are wrong.
		 */
		ret = -EFAULT;
		if (!iocb->aio_buf) {
			aio_sqring_unmap_iocb(ctx, i);
			goto err;
		}

		/* arbitrary limit, but we need something */
		if (iocb->aio_nbytes > SZ_4M) {
			aio_sqring_unmap_iocb(ctx, i);
			goto err;
		}

		ubuf = iocb->aio_buf;
		end = (ubuf + iocb->aio_nbytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
		aio_sqring_unmap_iocb(ctx, i);
		start = ubuf >> PAGE_SHIFT;
		nr_pages = end - start;

		ret = -ENOMEM;
		if (total_pages + nr_pages > page_limit)
			goto err;

		if (!pages || nr_pages > got_pages) {
			kfree(pages);
			pages = kmalloc(nr_pages * sizeof(struct page *),
					GFP_KERNEL);
			if (!pages)
				goto err;
			got_pages = nr_pages;
		}

		amu->bvec = kmalloc(nr_pages * sizeof(struct bio_vec),
					GFP_KERNEL);
		if (!amu->bvec)
			goto err;

		down_write(&current->mm->mmap_sem);
		pret = get_user_pages(ubuf, nr_pages, 1, pages, NULL);
		up_write(&current->mm->mmap_sem);

		if (pret < nr_pages) {
			if (pret < 0)
				ret = pret;
			goto err;
		}

		off = ubuf & ~PAGE_MASK;
		size = iocb->aio_nbytes;
		for (j = 0; j < nr_pages; j++) {
			size_t vec_len;

			vec_len = min_t(size_t, size, PAGE_SIZE - off);
			amu->bvec[j].bv_page = pages[j];
			amu->bvec[j].bv_len = vec_len;
			amu->bvec[j].bv_offset = off;
			off = 0;
			size -= vec_len;
		}
		/* store original address for later verification */
		amu->ubuf = ubuf;
		amu->len = iocb->aio_nbytes;
		amu->nr_bvecs = nr_pages;
		total_pages += nr_pages;
	}
	kfree(pages);
	return 0;
err:
	kfree(pages);
	aio_iocb_buffer_unmap(ctx);
	return ret;
}

/* sys_io_setup2:
 *	Like sys_io_setup(), except that it takes a set of flags
 *	(IOCTX_FLAG_*), and some pointers to user structures:
 *
 *	*sq_ring - pointer to the userspace SQ ring, if used.
 *
 *	*cq_ring - pointer to the userspace CQ ring, if used.
 */
SYSCALL_DEFINE5(io_setup2, u32, nr_events, u32, flags,
		struct aio_sq_ring __user *, sq_ring,
		struct aio_cq_ring __user *, cq_ring,
		aio_context_t __user *, ctxp)
{
	struct kioctx *ioctx;
	unsigned long ctx;
	long ret;

	if (flags & ~(IOCTX_FLAG_IOPOLL | IOCTX_FLAG_SCQRING |
		      IOCTX_FLAG_FIXEDBUFS | IOCTX_FLAG_SQTHREAD |
		      IOCTX_FLAG_SQWQ))
		return -EINVAL;

	ret = get_user(ctx, ctxp);
	if (unlikely(ret))
		goto out;

	ioctx = io_setup_flags(ctx, nr_events, flags);
	ret = PTR_ERR(ioctx);
	if (IS_ERR(ioctx))
		goto out;

	if (flags & IOCTX_FLAG_SCQRING) {
		ret = aio_scqring_map(ioctx, sq_ring, cq_ring);
		if (ret)
			goto err;
		if (flags & IOCTX_FLAG_FIXEDBUFS) {
			ret = aio_iocb_buffer_map(ioctx);
			if (ret)
				goto err;
		}
	} else if (flags & (IOCTX_FLAG_FIXEDBUFS | IOCTX_FLAG_SQTHREAD |
		            IOCTX_FLAG_SQWQ)) {
		/* These features only supported with SCQRING */
		ret = -EINVAL;
		goto err;
	}

	ret = put_user(ioctx->user_id, ctxp);
	if (ret) {
err:
		kill_ioctx(current->mm, ioctx, NULL);
	}
	percpu_ref_put(&ioctx->users);
out:
	return ret;
}

/* sys_io_setup:
 *	Create an aio_context capable of receiving at least nr_events.
 *	ctxp must not point to an aio_context that already exists, and
 *	must be initialized to 0 prior to the call.  On successful
 *	creation of the aio_context, *ctxp is filled in with the resulting 
 *	handle.  May fail with -EINVAL if *ctxp is not initialized,
 *	if the specified nr_events exceeds internal limits.  May fail 
 *	with -EAGAIN if the specified nr_events exceeds the user's limit 
 *	of available events.  May fail with -ENOMEM if insufficient kernel
 *	resources are available.  May fail with -EFAULT if an invalid
 *	pointer is passed for ctxp.  Will fail with -ENOSYS if not
 *	implemented.
 */
SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
{
	struct kioctx *ioctx;
	unsigned long ctx;
	long ret;

	ret = get_user(ctx, ctxp);
	if (unlikely(ret))
		goto out;

	ioctx = io_setup_flags(ctx, nr_events, 0);
	ret = PTR_ERR(ioctx);
	if (!IS_ERR(ioctx)) {
		ret = put_user(ioctx->user_id, ctxp);
		if (ret)
			kill_ioctx(current->mm, ioctx, NULL);
		percpu_ref_put(&ioctx->users);
	}

out:
	return ret;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(io_setup, unsigned, nr_events, u32 __user *, ctx32p)
{
	struct kioctx *ioctx;
	unsigned long ctx;
	long ret;

	ret = get_user(ctx, ctx32p);
	if (unlikely(ret))
		goto out;

	ioctx = io_setup_flags(ctx, nr_events, 0);
	ret = PTR_ERR(ioctx);
	if (!IS_ERR(ioctx)) {
		ret = put_user(ioctx->user_id, ctx32p);
		if (ret)
			kill_ioctx(current->mm, ioctx, NULL);
		percpu_ref_put(&ioctx->users);
	}
out:
	return ret;
}
#endif

/* sys_io_destroy:
 *	Destroy the aio_context specified.  May cancel any outstanding 
 *	AIOs and block on completion.  Will fail with -ENOSYS if not
 *	implemented.  May fail with -EINVAL if the context pointed to
 *	is invalid.
 */
SYSCALL_DEFINE1(io_destroy, aio_context_t, ctx)
{
	struct kioctx *ioctx = lookup_ioctx(ctx);
	if (likely(NULL != ioctx)) {
		struct ctx_rq_wait wait;
		int ret;

		init_completion(&wait.comp);
		atomic_set(&wait.count, 1);

		/* Pass requests_done to kill_ioctx() where it can be set
		 * in a thread-safe way. If we try to set it here then we have
		 * a race condition if two io_destroy() called simultaneously.
		 */
		ret = kill_ioctx(current->mm, ioctx, &wait);
		percpu_ref_put(&ioctx->users);

		/* Wait until all IO for the context are done. Otherwise kernel
		 * keep using user-space buffers even if user thinks the context
		 * is destroyed.
		 */
		if (!ret)
			wait_for_completion(&wait.comp);

		return ret;
	}
	pr_debug("EINVAL: invalid context id\n");
	return -EINVAL;
}

static void aio_remove_iocb(struct aio_kiocb *iocb)
{
	struct kioctx *ctx = iocb->ki_ctx;
	unsigned long flags;

	spin_lock_irqsave(&ctx->ctx_lock, flags);
	list_del(&iocb->ki_list);
	spin_unlock_irqrestore(&ctx->ctx_lock, flags);
}

static void kiocb_end_write(struct kiocb *kiocb)
{
	if (kiocb->ki_flags & IOCB_WRITE) {
		struct inode *inode = file_inode(kiocb->ki_filp);

		/*
		 * Tell lockdep we inherited freeze protection from submission
		 * thread.
		 */
		if (S_ISREG(inode->i_mode))
			__sb_writers_acquired(inode->i_sb, SB_FREEZE_WRITE);
		file_end_write(kiocb->ki_filp);
	}
}

static void aio_complete_rw(struct kiocb *kiocb, long res, long res2)
{
	struct aio_kiocb *iocb = container_of(kiocb, struct aio_kiocb, rw);

	if (!list_empty_careful(&iocb->ki_list))
		aio_remove_iocb(iocb);

	kiocb_end_write(kiocb);

	fput(kiocb->ki_filp);
	aio_complete(iocb, res, res2);
}

static void aio_complete_rw_poll(struct kiocb *kiocb, long res, long res2)
{
	struct aio_kiocb *iocb = container_of(kiocb, struct aio_kiocb, rw);

	kiocb_end_write(kiocb);

	if (unlikely(res == -EAGAIN)) {
		set_bit(KIOCB_F_POLL_EAGAIN, &iocb->ki_flags);
	} else {
		aio_fill_event(&iocb->ki_ev, iocb, res, res2);
		set_bit(KIOCB_F_POLL_COMPLETED, &iocb->ki_flags);
	}
}

static void aio_file_put(struct aio_submit_state *state, struct file *file)
{
	if (!state) {
		fput(file);
	} else if (state->file) {
		int diff = state->has_refs - state->used_refs;

		if (diff)
			fput_many(state->file, diff);
		state->file = NULL;
	}
}

/*
 * Get as many references to a file as we have IOs left in this submission,
 * assuming most submissions are for one file, or at least that each file
 * has more than one submission.
 */
static struct file *aio_file_get(struct aio_submit_state *state, int fd)
{
	if (!state)
		return fget(fd);

	if (!state->file) {
get_file:
		state->file = fget_many(fd, state->ios_left);
		if (!state->file)
			return NULL;

		state->fd = fd;
		state->has_refs = state->ios_left;
		state->used_refs = 1;
		state->ios_left--;
		return state->file;
	}

	if (state->fd == fd) {
		state->used_refs++;
		state->ios_left--;
		return state->file;
	}

	aio_file_put(state, NULL);
	goto get_file;
}

static int aio_prep_rw(struct aio_kiocb *kiocb, const struct iocb *iocb,
		       struct aio_submit_state *state, bool force_nonblock)
{
	struct kioctx *ctx = kiocb->ki_ctx;
	struct kiocb *req = &kiocb->rw;
	int ret;

	req->ki_filp = aio_file_get(state, iocb->aio_fildes);
	if (unlikely(!req->ki_filp))
		return -EBADF;
	req->ki_pos = iocb->aio_offset;
	req->ki_flags = iocb_flags(req->ki_filp);
	if (iocb->aio_flags & IOCB_FLAG_RESFD)
		req->ki_flags |= IOCB_EVENTFD;
	req->ki_hint = ki_hint_validate(file_write_hint(req->ki_filp));
	if (iocb->aio_flags & IOCB_FLAG_IOPRIO) {
		/*
		 * If the IOCB_FLAG_IOPRIO flag of aio_flags is set, then
		 * aio_reqprio is interpreted as an I/O scheduling
		 * class and priority.
		 */
		ret = ioprio_check_cap(iocb->aio_reqprio);
		if (ret) {
			pr_debug("aio ioprio check cap error: %d\n", ret);
			goto out_fput;
		}

		req->ki_ioprio = iocb->aio_reqprio;
	} else
		req->ki_ioprio = get_current_ioprio();

	ret = kiocb_set_rw_flags(req, iocb->aio_rw_flags);
	if (unlikely(ret))
		goto out_fput;
	if (force_nonblock) {
		req->ki_flags |= IOCB_NOWAIT;
		set_bit(KIOCB_F_FORCE_NONBLOCK, &kiocb->ki_flags);
	}

	if (ctx->flags & IOCTX_FLAG_IOPOLL) {
		/* shares space in the union, and is rather pointless.. */
		ret = -EINVAL;
		if (iocb->aio_flags & IOCB_FLAG_RESFD)
			goto out_fput;

		ret = -EOPNOTSUPP;
		if (!(req->ki_flags & IOCB_DIRECT) ||
		    !req->ki_filp->f_op->iopoll)
			goto out_fput;

		req->ki_flags |= IOCB_HIPRI;
		req->ki_complete = aio_complete_rw_poll;
	} else {
		/* can't submit non-polled IO to a polled ctx */
		ret = -EINVAL;
		if (ctx->flags & IOCTX_FLAG_IOPOLL)
			goto out_fput;

		/* no one is going to poll for this I/O */
		req->ki_flags &= ~IOCB_HIPRI;
		req->ki_complete = aio_complete_rw;
	}

	return 0;
out_fput:
	aio_file_put(state, req->ki_filp);
	return ret;
}

static int aio_setup_rw(int rw, struct aio_kiocb *kiocb,
		const struct iocb *iocb, struct iovec **iovec, bool vectored,
		bool compat, bool kaddr, struct iov_iter *iter)
{
	void __user *ubuf = (void __user *)(uintptr_t)iocb->aio_buf;
	size_t len = iocb->aio_nbytes;

	if (!vectored) {
		ssize_t ret;

		if (!kaddr) {
			ret = import_single_range(rw, ubuf, len, *iovec, iter);
		} else {
			struct kioctx *ctx = kiocb->ki_ctx;
			struct aio_mapped_ubuf *amu;
			size_t offset;
			int index;

			/* __io_submit_one() already validated the index */
			index = array_index_nospec(kiocb->ki_index,
							ctx->max_reqs);
			amu = &ctx->user_bufs[index];
			if (iocb->aio_buf < amu->ubuf ||
			    iocb->aio_buf + len > amu->ubuf + amu->len) {
				ret = -EFAULT;
				goto err;
			}

			/*
			 * May not be a start of buffer, set size appropriately
			 * and advance us to the beginning.
			 */
			offset = iocb->aio_buf - amu->ubuf;
			iov_iter_bvec(iter, rw, amu->bvec, amu->nr_bvecs,
					offset + len);
			if (offset)
				iov_iter_advance(iter, offset);
			ret = 0;

		}
err:
		*iovec = NULL;
		return ret;
	}
	if (kaddr)
		return -EINVAL;
#ifdef CONFIG_COMPAT
	if (compat)
		return compat_import_iovec(rw, ubuf, len, UIO_FASTIOV, iovec,
				iter);
#endif
	return import_iovec(rw, ubuf, len, UIO_FASTIOV, iovec, iter);
}

static inline void aio_rw_done(struct kiocb *req, ssize_t ret)
{
	switch (ret) {
	case -EIOCBQUEUED:
		break;
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
	case -ERESTARTNOHAND:
	case -ERESTART_RESTARTBLOCK:
		/*
		 * There's no easy way to restart the syscall since other AIO's
		 * may be already running. Just fail this IO with EINTR.
		 */
		ret = -EINTR;
		/*FALLTHRU*/
	default:
		req->ki_complete(req, ret, 0);
	}
}

/*
 * Called either at the end of IO submission, or through a plug callback
 * because we're going to schedule. Moves out local batch of requests to
 * the ctx poll list, so they can be found for polling + reaping.
 */
static void aio_flush_state_reqs(struct kioctx *ctx,
				 struct aio_submit_state *state)
{
	spin_lock(&ctx->poll_lock);
	list_splice_tail_init(&state->req_list, &ctx->poll_submitted);
	spin_unlock(&ctx->poll_lock);
	state->req_count = 0;
}

static void aio_iopoll_iocb_add_list(struct aio_kiocb *kiocb)
{
	struct kioctx *ctx = kiocb->ki_ctx;

	/*
	 * For fast devices, IO may have already completed. If it has, add
	 * it to the front so we find it first. We can't add to the poll_done
	 * list as that's unlocked from the completion side.
	 */
	spin_lock(&ctx->poll_lock);
	if (test_bit(KIOCB_F_POLL_COMPLETED, &kiocb->ki_flags))
		list_add(&kiocb->ki_list, &ctx->poll_submitted);
	else
		list_add_tail(&kiocb->ki_list, &ctx->poll_submitted);
	spin_unlock(&ctx->poll_lock);
}

static void aio_iopoll_iocb_add_state(struct aio_submit_state *state,
				      struct aio_kiocb *kiocb)
{
	if (test_bit(KIOCB_F_POLL_COMPLETED, &kiocb->ki_flags))
		list_add(&kiocb->ki_list, &state->req_list);
	else
		list_add_tail(&kiocb->ki_list, &state->req_list);

	if (++state->req_count >= AIO_IOPOLL_BATCH)
		aio_flush_state_reqs(state->ctx, state);
}
/*
 * After the iocb has been issued, it's safe to be found on the poll list.
 * Adding the kiocb to the list AFTER submission ensures that we don't
 * find it from a io_getevents() thread before the issuer is done accessing
 * the kiocb cookie.
 */
static void aio_iopoll_iocb_issued(struct aio_submit_state *state,
				   struct aio_kiocb *kiocb)
{
	if (!state || !IS_ENABLED(CONFIG_BLOCK))
		aio_iopoll_iocb_add_list(kiocb);
	else
		aio_iopoll_iocb_add_state(state, kiocb);
}

static ssize_t aio_read(struct aio_kiocb *kiocb, const struct iocb *iocb,
			struct aio_submit_state *state, bool vectored,
			bool compat, bool kaddr, bool force_nonblock)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *req = &kiocb->rw;
	struct iov_iter iter;
	struct file *file;
	ssize_t ret;

	ret = aio_prep_rw(kiocb, iocb, state, force_nonblock);
	if (ret)
		return ret;
	file = req->ki_filp;

	ret = -EBADF;
	if (unlikely(!(file->f_mode & FMODE_READ)))
		goto out_fput;
	ret = -EINVAL;
	if (unlikely(!file->f_op->read_iter))
		goto out_fput;

	ret = aio_setup_rw(READ, kiocb, iocb, &iovec, vectored, compat, kaddr,
				&iter);
	if (ret)
		goto out_fput;

	ret = rw_verify_area(READ, file, &req->ki_pos, iov_iter_count(&iter));
	if (!ret)
		aio_rw_done(req, call_read_iter(file, req, &iter));
	kfree(iovec);
out_fput:
	if (unlikely(ret))
		fput(file);
	return ret;
}

static ssize_t aio_write(struct aio_kiocb *kiocb, const struct iocb *iocb,
			 struct aio_submit_state *state, bool vectored,
			 bool compat, bool kaddr)
{
	struct iovec inline_vecs[UIO_FASTIOV], *iovec = inline_vecs;
	struct kiocb *req = &kiocb->rw;
	struct iov_iter iter;
	struct file *file;
	ssize_t ret;

	ret = aio_prep_rw(kiocb, iocb, state, false);
	if (ret)
		return ret;
	file = req->ki_filp;

	ret = -EBADF;
	if (unlikely(!(file->f_mode & FMODE_WRITE)))
		goto out_fput;
	ret = -EINVAL;
	if (unlikely(!file->f_op->write_iter))
		goto out_fput;

	ret = aio_setup_rw(WRITE, kiocb, iocb, &iovec, vectored, compat, kaddr,
				&iter);
	if (ret)
		goto out_fput;
	ret = rw_verify_area(WRITE, file, &req->ki_pos, iov_iter_count(&iter));
	if (!ret) {
		/*
		 * Open-code file_start_write here to grab freeze protection,
		 * which will be released by another thread in
		 * aio_complete_rw().  Fool lockdep by telling it the lock got
		 * released so that it doesn't complain about the held lock when
		 * we return to userspace.
		 */
		if (S_ISREG(file_inode(file)->i_mode)) {
			__sb_start_write(file_inode(file)->i_sb, SB_FREEZE_WRITE, true);
			__sb_writers_release(file_inode(file)->i_sb, SB_FREEZE_WRITE);
		}
		req->ki_flags |= IOCB_WRITE;
		aio_rw_done(req, call_write_iter(file, req, &iter));
	}
	kfree(iovec);
out_fput:
	if (unlikely(ret))
		fput(file);
	return ret;
}

static void aio_fsync_work(struct work_struct *work)
{
	struct fsync_iocb *req = container_of(work, struct fsync_iocb, work);
	int ret;

	ret = vfs_fsync(req->file, req->datasync);
	fput(req->file);
	aio_complete(container_of(req, struct aio_kiocb, fsync), ret, 0);
}

static int aio_fsync(struct fsync_iocb *req, const struct iocb *iocb,
		     bool datasync)
{
	if (unlikely(iocb->aio_buf || iocb->aio_offset || iocb->aio_nbytes ||
			iocb->aio_rw_flags))
		return -EINVAL;

	req->file = fget(iocb->aio_fildes);
	if (unlikely(!req->file))
		return -EBADF;
	if (unlikely(!req->file->f_op->fsync)) {
		fput(req->file);
		return -EINVAL;
	}

	req->datasync = datasync;
	INIT_WORK(&req->work, aio_fsync_work);
	schedule_work(&req->work);
	return 0;
}

static inline void aio_poll_complete(struct aio_kiocb *iocb, __poll_t mask)
{
	struct file *file = iocb->poll.file;

	aio_complete(iocb, mangle_poll(mask), 0);
	fput(file);
}

static void aio_poll_complete_work(struct work_struct *work)
{
	struct poll_iocb *req = container_of(work, struct poll_iocb, work);
	struct aio_kiocb *iocb = container_of(req, struct aio_kiocb, poll);
	struct poll_table_struct pt = { ._key = req->events };
	struct kioctx *ctx = iocb->ki_ctx;
	__poll_t mask = 0;

	if (!READ_ONCE(req->cancelled))
		mask = vfs_poll(req->file, &pt) & req->events;

	/*
	 * Note that ->ki_cancel callers also delete iocb from active_reqs after
	 * calling ->ki_cancel.  We need the ctx_lock roundtrip here to
	 * synchronize with them.  In the cancellation case the list_del_init
	 * itself is not actually needed, but harmless so we keep it in to
	 * avoid further branches in the fast path.
	 */
	spin_lock_irq(&ctx->ctx_lock);
	if (!mask && !READ_ONCE(req->cancelled)) {
		add_wait_queue(req->head, &req->wait);
		spin_unlock_irq(&ctx->ctx_lock);
		return;
	}
	list_del_init(&iocb->ki_list);
	spin_unlock_irq(&ctx->ctx_lock);

	aio_poll_complete(iocb, mask);
}

/* assumes we are called with irqs disabled */
static int aio_poll_cancel(struct kiocb *iocb)
{
	struct aio_kiocb *aiocb = container_of(iocb, struct aio_kiocb, rw);
	struct poll_iocb *req = &aiocb->poll;

	spin_lock(&req->head->lock);
	WRITE_ONCE(req->cancelled, true);
	if (!list_empty(&req->wait.entry)) {
		list_del_init(&req->wait.entry);
		schedule_work(&aiocb->poll.work);
	}
	spin_unlock(&req->head->lock);

	return 0;
}

static int aio_poll_wake(struct wait_queue_entry *wait, unsigned mode, int sync,
		void *key)
{
	struct poll_iocb *req = container_of(wait, struct poll_iocb, wait);
	struct aio_kiocb *iocb = container_of(req, struct aio_kiocb, poll);
	__poll_t mask = key_to_poll(key);

	req->woken = true;

	/* for instances that support it check for an event match first: */
	if (mask) {
		if (!(mask & req->events))
			return 0;

		/* try to complete the iocb inline if we can: */
		if (spin_trylock(&iocb->ki_ctx->ctx_lock)) {
			list_del(&iocb->ki_list);
			spin_unlock(&iocb->ki_ctx->ctx_lock);

			list_del_init(&req->wait.entry);
			aio_poll_complete(iocb, mask);
			return 1;
		}
	}

	list_del_init(&req->wait.entry);
	schedule_work(&req->work);
	return 1;
}

struct aio_poll_table {
	struct poll_table_struct	pt;
	struct aio_kiocb		*iocb;
	int				error;
};

static void
aio_poll_queue_proc(struct file *file, struct wait_queue_head *head,
		struct poll_table_struct *p)
{
	struct aio_poll_table *pt = container_of(p, struct aio_poll_table, pt);

	/* multiple wait queues per file are not supported */
	if (unlikely(pt->iocb->poll.head)) {
		pt->error = -EINVAL;
		return;
	}

	pt->error = 0;
	pt->iocb->poll.head = head;
	add_wait_queue(head, &pt->iocb->poll.wait);
}

static ssize_t aio_poll(struct aio_kiocb *aiocb, const struct iocb *iocb)
{
	struct kioctx *ctx = aiocb->ki_ctx;
	struct poll_iocb *req = &aiocb->poll;
	struct aio_poll_table apt;
	__poll_t mask;

	/* reject any unknown events outside the normal event mask. */
	if ((u16)iocb->aio_buf != iocb->aio_buf)
		return -EINVAL;
	/* reject fields that are not defined for poll */
	if (iocb->aio_offset || iocb->aio_nbytes || iocb->aio_rw_flags)
		return -EINVAL;

	INIT_WORK(&req->work, aio_poll_complete_work);
	req->events = demangle_poll(iocb->aio_buf) | EPOLLERR | EPOLLHUP;
	req->file = fget(iocb->aio_fildes);
	if (unlikely(!req->file))
		return -EBADF;

	req->head = NULL;
	req->woken = false;
	req->cancelled = false;

	apt.pt._qproc = aio_poll_queue_proc;
	apt.pt._key = req->events;
	apt.iocb = aiocb;
	apt.error = -EINVAL; /* same as no support for IOCB_CMD_POLL */

	/* initialized the list so that we can do list_empty checks */
	INIT_LIST_HEAD(&req->wait.entry);
	init_waitqueue_func_entry(&req->wait, aio_poll_wake);

	/* one for removal from waitqueue, one for this function */
	refcount_set(&aiocb->ki_refcnt, 2);

	mask = vfs_poll(req->file, &apt.pt) & req->events;
	if (unlikely(!req->head)) {
		/* we did not manage to set up a waitqueue, done */
		goto out;
	}

	spin_lock_irq(&ctx->ctx_lock);
	spin_lock(&req->head->lock);
	if (req->woken) {
		/* wake_up context handles the rest */
		mask = 0;
		apt.error = 0;
	} else if (mask || apt.error) {
		/* if we get an error or a mask we are done */
		WARN_ON_ONCE(list_empty(&req->wait.entry));
		list_del_init(&req->wait.entry);
	} else {
		/* actually waiting for an event */
		list_add_tail(&aiocb->ki_list, &ctx->active_reqs);
		aiocb->ki_cancel = aio_poll_cancel;
	}
	spin_unlock(&req->head->lock);
	spin_unlock_irq(&ctx->ctx_lock);

out:
	if (unlikely(apt.error)) {
		fput(req->file);
		return apt.error;
	}

	if (mask)
		aio_poll_complete(aiocb, mask);
	iocb_put(aiocb);
	return 0;
}

static int __io_submit_one(struct kioctx *ctx, const struct iocb *iocb,
			   unsigned long ki_index,
			   struct aio_submit_state *state, bool compat,
			   bool kaddr, bool force_nonblock)
{
	struct aio_kiocb *req;
	ssize_t ret;

	/* enforce forwards compatibility on users */
	if (unlikely(iocb->aio_reserved2)) {
		pr_debug("EINVAL: reserve field set\n");
		return -EINVAL;
	}

	/* prevent overflows */
	if (unlikely(
	    (iocb->aio_buf != (unsigned long)iocb->aio_buf) ||
	    (iocb->aio_nbytes != (size_t)iocb->aio_nbytes) ||
	    ((ssize_t)iocb->aio_nbytes < 0)
	   )) {
		pr_debug("EINVAL: overflow check\n");
		return -EINVAL;
	}

	if (aio_ctx_old_ring(ctx) && !get_reqs_available(ctx))
		return -EAGAIN;

	ret = -EAGAIN;
	req = aio_get_req(ctx, state);
	if (unlikely(!req))
		goto out_put_reqs_available;

	if (iocb->aio_flags & IOCB_FLAG_RESFD) {
		/*
		 * If the IOCB_FLAG_RESFD flag of aio_flags is set, get an
		 * instance of the file* now. The file descriptor must be
		 * an eventfd() fd, and will be signaled for each completed
		 * event using the eventfd_signal() function.
		 */
		req->ki_eventfd = eventfd_ctx_fdget((int) iocb->aio_resfd);
		if (IS_ERR(req->ki_eventfd)) {
			ret = PTR_ERR(req->ki_eventfd);
			req->ki_eventfd = NULL;
			goto out_put_req;
		}
	}

	if (aio_ctx_supports_cancel(ctx)) {
		struct iocb __user *user_iocb = (struct iocb __user *) ki_index;

		ret = put_user(KIOCB_KEY, &user_iocb->aio_key);
		if (unlikely(ret)) {
			pr_debug("EFAULT: aio_key\n");
			goto out_put_req;
		}
		req->ki_user_iocb = user_iocb;
	} else {
		ret = -EINVAL;
		if (ki_index >= ctx->max_reqs)
			goto out_put_req;
		req->ki_index = ki_index;
	}

	req->ki_user_data = iocb->aio_data;

	ret = -EINVAL;
	switch (iocb->aio_lio_opcode) {
	case IOCB_CMD_PREAD:
		ret = aio_read(req, iocb, state, false, compat, kaddr,
				force_nonblock);
		break;
	case IOCB_CMD_PWRITE:
		ret = aio_write(req, iocb, state, false, compat, kaddr);
		break;
	case IOCB_CMD_PREADV:
		ret = aio_read(req, iocb, state, true, compat, kaddr,
				force_nonblock);
		break;
	case IOCB_CMD_PWRITEV:
		ret = aio_write(req, iocb, state, true, compat, kaddr);
		break;
	case IOCB_CMD_FSYNC:
		if (ctx->flags & IOCTX_FLAG_IOPOLL)
			break;
		ret = aio_fsync(&req->fsync, iocb, false);
		break;
	case IOCB_CMD_FDSYNC:
		if (ctx->flags & IOCTX_FLAG_IOPOLL)
			break;
		ret = aio_fsync(&req->fsync, iocb, true);
		break;
	case IOCB_CMD_POLL:
		if (ctx->flags & IOCTX_FLAG_IOPOLL)
			break;
		ret = aio_poll(req, iocb);
		break;
	default:
		pr_debug("invalid aio operation %d\n", iocb->aio_lio_opcode);
		ret = -EINVAL;
		break;
	}

	/*
	 * If ret is 0, we'd either done aio_complete() ourselves or have
	 * arranged for that to be done asynchronously.  Anything non-zero
	 * means that we need to destroy req ourselves.
	 */
	if (ret)
		goto out_put_req;
	if (ctx->flags & IOCTX_FLAG_IOPOLL) {
		if (test_bit(KIOCB_F_POLL_EAGAIN, &req->ki_flags)) {
			ret = -EAGAIN;
			goto out_put_req;
		}
		aio_iopoll_iocb_issued(state, req);
	}
	return 0;
out_put_req:
	if (req->ki_eventfd)
		eventfd_ctx_put(req->ki_eventfd);
	iocb_put(req);
out_put_reqs_available:
	if (aio_ctx_old_ring(ctx))
		put_reqs_available(ctx, 1);
	return ret;
}

static int io_submit_one(struct kioctx *ctx, struct iocb __user *user_iocb,
			 struct aio_submit_state *state, bool compat)
{
	unsigned long ki_index = (unsigned long) user_iocb;
	struct iocb iocb;

	if (unlikely(copy_from_user(&iocb, user_iocb, sizeof(iocb))))
		return -EFAULT;

	return __io_submit_one(ctx, &iocb, ki_index, state, compat, false,
				false);
}

#ifdef CONFIG_BLOCK
static void aio_state_unplug(struct blk_plug_cb *cb, bool from_schedule)
{
	struct aio_submit_state *state;

	state = container_of(cb, struct aio_submit_state, plug_cb);
	if (!list_empty(&state->req_list))
		aio_flush_state_reqs(state->ctx, state);
}
#endif

/*
 * Batched submission is done, ensure local IO is flushed out.
 */
static void aio_submit_state_end(struct aio_submit_state *state)
{
	blk_finish_plug(&state->plug);
	if (!list_empty(&state->req_list))
		aio_flush_state_reqs(state->ctx, state);
	aio_file_put(state, NULL);
	if (state->free_iocbs)
		kmem_cache_free_bulk(kiocb_cachep, state->free_iocbs,
					&state->iocbs[state->cur_iocb]);
}

/*
 * Start submission side cache.
 */
static void aio_submit_state_start(struct aio_submit_state *state,
				   struct kioctx *ctx, int max_ios)
{
	state->ctx = ctx;
	INIT_LIST_HEAD(&state->req_list);
	state->req_count = 0;
	state->free_iocbs = 0;
	state->file = NULL;
	state->ios_left = max_ios;
#ifdef CONFIG_BLOCK
	state->plug_cb.callback = aio_state_unplug;
	blk_start_plug(&state->plug);
	list_add(&state->plug_cb.list, &state->plug.cb_list);
#endif
}

static const struct iocb *aio_iocb_from_index(struct kioctx *ctx,
					      unsigned iocb_index)
{
	struct aio_mapped_range *range = &ctx->sq_ring.iocb_range;
	const struct iocb *iocb;

	iocb = kmap(range->pages[iocb_index >> iocb_page_shift]);
	iocb_index &= ((1 << iocb_page_shift) - 1);
	return iocb + iocb_index;
}

static void aio_sqring_unmap_iocb(struct kioctx *ctx, unsigned iocb_index)
{
	struct aio_mapped_range *range = &ctx->sq_ring.iocb_range;

	kunmap(range->pages[iocb_index >> iocb_page_shift]);
}

static void aio_commit_sqring(struct kioctx *ctx, unsigned iocb_index)
{
	struct aio_sq_ring *ring = aio_get_sqring(ctx);

	ring->head++;
	smp_wmb();
	aio_put_sqring(ctx, ring, true);

	aio_sqring_unmap_iocb(ctx, iocb_index);
}

static const struct iocb *aio_peek_sqring(struct kioctx *ctx,
					  unsigned *iocb_index)
{
	struct aio_mapped_range *range = &ctx->sq_ring.ring_range;
	struct aio_sq_ring *ring = aio_get_sqring(ctx);
	const struct iocb *iocb = NULL;
	unsigned head;
	u32 *array;

	smp_rmb();
	head = READ_ONCE(ring->head);
	if (head == READ_ONCE(ring->tail)) {
		aio_put_sqring(ctx, ring, false);
		return NULL;
	}

	/*
	 * No guarantee the array is in the first page, so we can't just
	 * index ring->array. Find the map and offset from the head.
	 */
	head &= ctx->sq_ring.ring_mask;
	head += offsetof(struct aio_sq_ring, array) >> 2;

	array = kmap_atomic(range->pages[head >> array_page_shift]);
	head &= ((1 << array_page_shift) - 1);
	*iocb_index = array[head];
	kunmap_atomic(array);

	if (*iocb_index < ring->nr_events) {
		aio_put_sqring(ctx, ring, false);
		iocb = aio_iocb_from_index(ctx, *iocb_index);
		return iocb;
	}

	/* drop invalid entries */
	ring->head++;
	smp_wmb();
	aio_put_sqring(ctx, ring, true);
	return NULL;
}

static int aio_ring_submit(struct kioctx *ctx, unsigned int to_submit)
{
	bool kaddr = (ctx->flags & IOCTX_FLAG_FIXEDBUFS) != 0;
	struct aio_submit_state state, *statep = NULL;
	int i, ret = 0, submit = 0;

	if (to_submit > AIO_PLUG_THRESHOLD) {
		aio_submit_state_start(&state, ctx, to_submit);
		statep = &state;
	}

	for (i = 0; i < to_submit; i++) {
		const struct iocb *iocb;
		unsigned iocb_index;

		iocb = aio_peek_sqring(ctx, &iocb_index);
		if (!iocb)
			break;

		ret = __io_submit_one(ctx, iocb, iocb_index, statep, false, kaddr,
					false);
		if (ret) {
			aio_sqring_unmap_iocb(ctx, iocb_index);
			break;
		}

		submit++;
		aio_commit_sqring(ctx, iocb_index);
	}

	if (statep)
		aio_submit_state_end(statep);

	return submit ? submit : ret;
}

/*
 * Wait until events become available, if we don't already have some. The
 * application must reap them itself, as they reside on the shared cq ring.
 */
static int aio_cqring_wait(struct kioctx *ctx, int min_events)
{
	struct aio_cq_ring *ring;
	DEFINE_WAIT(wait);
	int ret = 0;

	ring = kmap(ctx->cq_ring.ev_range.pages[0]);

	smp_rmb();
	if (ring->head != ring->tail)
		goto out;
	if (!min_events)
		goto out;

	do {
		prepare_to_wait(&ctx->wait, &wait, TASK_INTERRUPTIBLE);

		ret = 0;
		smp_rmb();
		if (ring->head != ring->tail)
			break;

		schedule();

		ret = -EINVAL;
		if (atomic_read(&ctx->dead))
			break;
		ret = -EINTR;
		if (signal_pending(current))
			break;
	} while (1);

	finish_wait(&ctx->wait, &wait);
out:
	kunmap(ctx->cq_ring.ev_range.pages[0]);
	return ret;
}

static void aio_fill_cq_error(struct kioctx *ctx, const struct iocb *iocb,
			      long ret)
{
	struct io_event *ev;

	/*
	 * Only really need the lock for non-polled IO, but this is an error
	 * so not worth checking. Just lock it so we know kernel access to
	 * the CQ ring is serialized.
	 */
	spin_lock_irq(&ctx->completion_lock);
	ev = aio_peek_cqring(ctx);
	ev->obj = iocb->aio_data;
	ev->data = 0;
	ev->res = ret;
	ev->res2 = 0;
	aio_commit_cqring(ctx, ev);
	spin_unlock_irq(&ctx->completion_lock);

	/*
	 * for thread offload, app could already be sleeping in io_ring_enter()
	 * before we get to flag the error. wake them up, if needed.
	 */
	if (ctx->flags & (IOCTX_FLAG_SQTHREAD | IOCTX_FLAG_SQWQ))
		if (waitqueue_active(&ctx->wait))
			wake_up(&ctx->wait);
}

struct iocb_submit {
	const struct iocb *iocb;
	unsigned int index;
};

static int aio_submit_iocbs(struct kioctx *ctx, struct iocb_submit *iocbs,
			    unsigned int nr, struct mm_struct *cur_mm,
			    bool mm_fault)
{
	struct aio_submit_state state, *statep = NULL;
	int ret, i, submitted = 0;

	if (nr > AIO_PLUG_THRESHOLD) {
		aio_submit_state_start(&state, ctx, nr);
		statep = &state;
	}

	for (i = 0; i < nr; i++) {
		if (unlikely(mm_fault))
			ret = -EFAULT;
		else
			ret = __io_submit_one(ctx, iocbs[i].iocb,
						iocbs[i].index, statep, false,
						!cur_mm, false);
		if (!ret) {
			submitted++;
			continue;
		}

		aio_fill_cq_error(ctx, iocbs[i].iocb, ret);
	}

	if (statep)
		aio_submit_state_end(&state);

	return submitted;
}

/*
 * sq thread only supports O_DIRECT or FIXEDBUFS IO
 */
static int aio_sq_thread(void *data)
{
	struct iocb_submit iocbs[AIO_IOPOLL_BATCH];
	struct kioctx *ctx = data;
	struct aio_sq_offload *aso = &ctx->sq_offload;
	struct mm_struct *cur_mm = NULL;
	struct files_struct *old_files;
	mm_segment_t old_fs;
	DEFINE_WAIT(wait);

	old_files = current->files;
	current->files = aso->files;

	old_fs = get_fs();
	set_fs(USER_DS);

	while (!kthread_should_stop()) {
		const struct iocb *iocb;
		bool mm_fault = false;
		unsigned iocb_index;
		int i;

		iocb = aio_peek_sqring(ctx, &iocb_index);
		if (!iocb) {
			prepare_to_wait(&aso->wait, &wait, TASK_INTERRUPTIBLE);
			iocb = aio_peek_sqring(ctx, &iocb_index);
			if (!iocb) {
				/*
				 * Drop cur_mm before scheduler. We can't hold
				 * it for long periods, and it would also
				 * introduce a deadlock with kill_ioctx().
				 */
				if (cur_mm) {
					unuse_mm(cur_mm);
					mmput(cur_mm);
					cur_mm = NULL;
				}
				if (kthread_should_park())
					kthread_parkme();
				if (kthread_should_stop()) {
					finish_wait(&aso->wait, &wait);
					break;
				}
				if (signal_pending(current))
					flush_signals(current);
				schedule();
			}
			finish_wait(&aso->wait, &wait);
			if (!iocb)
				continue;
		}

		/* If ->mm is set, we're not doing FIXEDBUFS */
		if (aso->mm && !cur_mm) {
			mm_fault = !mmget_not_zero(aso->mm);
			if (!mm_fault) {
				use_mm(aso->mm);
				cur_mm = aso->mm;
			}
		}

		i = 0;
		do {
			if (i == ARRAY_SIZE(iocbs))
				break;
			iocbs[i].iocb = iocb;
			iocbs[i].index = iocb_index;
			++i;
			aio_commit_sqring(ctx, iocb_index);
		} while ((iocb = aio_peek_sqring(ctx, &iocb_index)) != NULL);

		aio_submit_iocbs(ctx, iocbs, i, cur_mm, mm_fault);
	}
	current->files = old_files;
	set_fs(old_fs);
	if (cur_mm) {
		unuse_mm(cur_mm);
		mmput(cur_mm);
	}
	return 0;
}

struct aio_io_work {
	struct work_struct work;
	struct kioctx *ctx;
	struct iocb iocb;
	unsigned iocb_index;
};

static void aio_sq_wq_submit_work(struct work_struct *work)
{
	struct aio_io_work *aiw = container_of(work, struct aio_io_work, work);
	struct kioctx *ctx = aiw->ctx;
	struct aio_sq_offload *aso = &ctx->sq_offload;
	mm_segment_t old_fs = get_fs();
	struct files_struct *old_files;
	int ret;

	old_files = current->files;
	current->files = aso->files;

	if (aso->mm) {
		if (!mmget_not_zero(aso->mm)) {
			ret = -EFAULT;
			goto err;
		}
		use_mm(aso->mm);
	}

	set_fs(USER_DS);

	ret = __io_submit_one(ctx, &aiw->iocb, aiw->iocb_index, NULL, false,
				!aso->mm, false);

	set_fs(old_fs);
	if (aso->mm) {
		unuse_mm(aso->mm);
		mmput(aso->mm);
	}

err:
	if (ret)
		aio_fill_cq_error(ctx, &aiw->iocb, ret);
	current->files = old_files;
	kfree(aiw);
}

/*
 * If this is a read, try a cached inline read first. If the IO is in the
 * page cache, we can satisfy it without blocking and without having to
 * punt to a threaded execution. This is much faster, particularly for
 * lower queue depth IO, and it's always a lot more efficient.
 */
static bool aio_sq_try_inline(struct kioctx *ctx, const struct iocb *iocb,
			      unsigned index)
{
	struct aio_sq_offload *aso = &ctx->sq_offload;
	int ret;

	if (iocb->aio_lio_opcode != IOCB_CMD_PREAD &&
	    iocb->aio_lio_opcode != IOCB_CMD_PREADV)
		return false;

	ret = __io_submit_one(ctx, iocb, index, NULL, false, !aso->mm, true);
	if (ret == -EAGAIN || ctx->sq_ring.submit_eagain) {
		ctx->sq_ring.submit_eagain = false;
		return false;
	}

	/*
	 * We're done - even if this was an error, return 0. The error will
	 * be in the CQ ring for the application.
	 */
	return true;
}

static int aio_sq_wq_submit(struct kioctx *ctx, unsigned int to_submit)
{
	struct aio_io_work *work;
	const struct iocb *iocb;
	unsigned iocb_index;
	int ret, queued;

	ret = queued = 0;
	while ((iocb = aio_peek_sqring(ctx, &iocb_index)) != NULL) {
		ret = aio_sq_try_inline(ctx, iocb, iocb_index);
		if (!ret) {
			work = kmalloc(sizeof(*work), GFP_KERNEL);
			if (!work) {
				ret = -ENOMEM;
				break;
			}
			memcpy(&work->iocb, iocb, sizeof(*iocb));
			aio_commit_sqring(ctx, iocb_index);
			work->iocb_index = iocb_index;
			INIT_WORK(&work->work, aio_sq_wq_submit_work);
			work->ctx = ctx;
			queue_work(ctx->sq_offload.wq, &work->work);
		}
		queued++;
		if (queued == to_submit)
			break;
	}

	return queued ? queued : ret;
}

static int __io_ring_enter(struct kioctx *ctx, unsigned int to_submit,
			   unsigned int min_complete, unsigned int flags)
{
	int ret = 0;

	if (to_submit) {
		if (!to_submit)
			return 0;

		/*
		 * Three options here:
		 * 1) We have an sq thread, just wake it up to do submissions
		 * 2) We have an sq wq, queue a work item for each iocb
		 * 3) Submit directly
		 */
		if (ctx->flags & IOCTX_FLAG_SQTHREAD) {
			wake_up(&ctx->sq_offload.wait);
			ret = to_submit;
		} else if (ctx->flags & IOCTX_FLAG_SQWQ) {
			ret = aio_sq_wq_submit(ctx, to_submit);
		} else {
			ret = aio_ring_submit(ctx, to_submit);
			if (ret < 0)
				return ret;
		}
	}
	if (flags & IORING_FLAG_GETEVENTS) {
		unsigned int nr_events = 0;
		int get_ret;

		if (!ret && to_submit)
			min_complete = 0;

		if (ctx->flags & IOCTX_FLAG_IOPOLL)
			get_ret = __aio_iopoll_check(ctx, NULL, &nr_events,
							min_complete, -1U);
		else
			get_ret = aio_cqring_wait(ctx, min_complete);

		if (get_ret < 0 && !ret)
			ret = get_ret;
	}

	return ret;
}

/* sys_io_ring_enter:
 *	Alternative way to both submit and complete IO, instead of using
 *	io_submit(2) and io_getevents(2). Requires the use of the SQ/CQ
 *	ring interface, hence the io_context must be setup with
 *	io_setup2() and IOCTX_FLAG_SCQRING must be specified (and the
 *	sq_ring/cq_ring passed in).
 *
 *	Returns the number of IOs submitted, if asked to submit IO,
 *	otherwise returns 0 for IORING_FLAG_GETEVENTS success,
 *	but not the number of events, as those will have to be found
 *	by the application by reading the CQ ring anyway.
 *
 *	Apart from that, the error returns are much like io_submit()
 *	and io_getevents(), since a lot of the same error conditions
 *	are shared.
 */
SYSCALL_DEFINE4(io_ring_enter, aio_context_t, ctx_id, u32, to_submit,
		u32, min_complete, u32, flags)
{
	struct kioctx *ctx;
	long ret;

	ctx = lookup_ioctx(ctx_id);
	if (!ctx) {
		pr_debug("EINVAL: invalid context id\n");
		return -EINVAL;
	}

	ret = -EBUSY;
	if (!mutex_trylock(&ctx->getevents_lock))
		goto err;

	ret = -EOVERFLOW;
	if (ctx->cq_ring.overflow) {
		ctx->cq_ring.overflow = false;
		goto err_unlock;
	}

	ret = -EINVAL;
	if (unlikely(atomic_read(&ctx->dead)))
		goto err_unlock;

	if (ctx->flags & IOCTX_FLAG_SCQRING)
		ret = __io_ring_enter(ctx, to_submit, min_complete, flags);

err_unlock:
	mutex_unlock(&ctx->getevents_lock);
err:
	percpu_ref_put(&ctx->users);
	return ret;
}

/* sys_io_submit:
 *	Queue the nr iocbs pointed to by iocbpp for processing.  Returns
 *	the number of iocbs queued.  May return -EINVAL if the aio_context
 *	specified by ctx_id is invalid, if nr is < 0, if the iocb at
 *	*iocbpp[0] is not properly initialized, if the operation specified
 *	is invalid for the file descriptor in the iocb.  May fail with
 *	-EFAULT if any of the data structures point to invalid data.  May
 *	fail with -EBADF if the file descriptor specified in the first
 *	iocb is invalid.  May fail with -EAGAIN if insufficient resources
 *	are available to queue any iocbs.  Will return 0 if nr is 0.  Will
 *	fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE3(io_submit, aio_context_t, ctx_id, long, nr,
		struct iocb __user * __user *, iocbpp)
{
	struct aio_submit_state state, *statep = NULL;
	struct kioctx *ctx;
	long ret = 0;
	int i = 0;

	if (unlikely(nr < 0))
		return -EINVAL;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx)) {
		pr_debug("EINVAL: invalid context id\n");
		return -EINVAL;
	}

	/* SCQRING must use io_ring_enter() */
	if (ctx->flags & IOCTX_FLAG_SCQRING)
		return -EINVAL;

	if (nr > ctx->nr_events)
		nr = ctx->nr_events;

	if (nr > AIO_PLUG_THRESHOLD) {
		aio_submit_state_start(&state, ctx, nr);
		statep = &state;
	}
	for (i = 0; i < nr; i++) {
		struct iocb __user *user_iocb;

		if (unlikely(get_user(user_iocb, iocbpp + i))) {
			ret = -EFAULT;
			break;
		}

		ret = io_submit_one(ctx, user_iocb, statep, false);
		if (ret)
			break;
	}
	if (statep)
		aio_submit_state_end(statep);

	percpu_ref_put(&ctx->users);
	return i ? i : ret;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE3(io_submit, compat_aio_context_t, ctx_id,
		       int, nr, compat_uptr_t __user *, iocbpp)
{
	struct aio_submit_state state, *statep = NULL;
	struct kioctx *ctx;
	long ret = 0;
	int i = 0;

	if (unlikely(nr < 0))
		return -EINVAL;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx)) {
		pr_debug("EINVAL: invalid context id\n");
		return -EINVAL;
	}

	if (nr > ctx->nr_events)
		nr = ctx->nr_events;

	if (nr > AIO_PLUG_THRESHOLD) {
		aio_submit_state_start(&state, ctx, nr);
		statep = &state;
	}
	for (i = 0; i < nr; i++) {
		compat_uptr_t user_iocb;

		if (unlikely(get_user(user_iocb, iocbpp + i))) {
			ret = -EFAULT;
			break;
		}

		ret = io_submit_one(ctx, compat_ptr(user_iocb), statep, true);
		if (ret)
			break;
	}
	if (statep)
		aio_submit_state_end(statep);

	percpu_ref_put(&ctx->users);
	return i ? i : ret;
}
#endif

/* lookup_kiocb
 *	Finds a given iocb for cancellation.
 */
static struct aio_kiocb *
lookup_kiocb(struct kioctx *ctx, struct iocb __user *iocb)
{
	struct aio_kiocb *kiocb;

	assert_spin_locked(&ctx->ctx_lock);

	/* TODO: use a hash or array, this sucks. */
	list_for_each_entry(kiocb, &ctx->active_reqs, ki_list) {
		if (kiocb->ki_user_iocb == iocb)
			return kiocb;
	}
	return NULL;
}

/* sys_io_cancel:
 *	Attempts to cancel an iocb previously passed to io_submit.  If
 *	the operation is successfully cancelled, the resulting event is
 *	copied into the memory pointed to by result without being placed
 *	into the completion queue and 0 is returned.  May fail with
 *	-EFAULT if any of the data structures pointed to are invalid.
 *	May fail with -EINVAL if aio_context specified by ctx_id is
 *	invalid.  May fail with -EAGAIN if the iocb specified was not
 *	cancelled.  Will fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
		struct io_event __user *, result)
{
	struct kioctx *ctx;
	struct aio_kiocb *kiocb;
	int ret = -EINVAL;
	u32 key;

	if (unlikely(get_user(key, &iocb->aio_key)))
		return -EFAULT;
	if (unlikely(key != KIOCB_KEY))
		return -EINVAL;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx))
		return -EINVAL;

	if (!aio_ctx_supports_cancel(ctx))
		goto err;

	spin_lock_irq(&ctx->ctx_lock);
	kiocb = lookup_kiocb(ctx, iocb);
	if (kiocb) {
		ret = kiocb->ki_cancel(&kiocb->rw);
		list_del_init(&kiocb->ki_list);
	}
	spin_unlock_irq(&ctx->ctx_lock);

	if (!ret) {
		/*
		 * The result argument is no longer used - the io_event is
		 * always delivered via the ring buffer. -EINPROGRESS indicates
		 * cancellation is progress:
		 */
		ret = -EINPROGRESS;
	}
err:
	percpu_ref_put(&ctx->users);
	return ret;
}

static long do_io_getevents(aio_context_t ctx_id,
		long min_nr,
		long nr,
		struct io_event __user *events,
		struct timespec64 *ts)
{
	ktime_t until = ts ? timespec64_to_ktime(*ts) : KTIME_MAX;
	struct kioctx *ioctx = lookup_ioctx(ctx_id);
	long ret = -EINVAL;

	if (likely(ioctx)) {
		/* SCQRING must use io_ring_enter() */
		if (ioctx->flags & IOCTX_FLAG_SCQRING)
			ret = -EINVAL;
		else if (min_nr <= nr && min_nr >= 0) {
			if (ioctx->flags & IOCTX_FLAG_IOPOLL)
				ret = aio_iopoll_check(ioctx, min_nr, nr, events);
			else
				ret = read_events(ioctx, min_nr, nr, events, until);
		}
		percpu_ref_put(&ioctx->users);
	}

	return ret;
}

/* io_getevents:
 *	Attempts to read at least min_nr events and up to nr events from
 *	the completion queue for the aio_context specified by ctx_id. If
 *	it succeeds, the number of read events is returned. May fail with
 *	-EINVAL if ctx_id is invalid, if min_nr is out of range, if nr is
 *	out of range, if timeout is out of range.  May fail with -EFAULT
 *	if any of the memory specified is invalid.  May return 0 or
 *	< min_nr if the timeout specified by timeout has elapsed
 *	before sufficient events are available, where timeout == NULL
 *	specifies an infinite timeout. Note that the timeout pointed to by
 *	timeout is relative.  Will fail with -ENOSYS if not implemented.
 */
#if !defined(CONFIG_64BIT_TIME) || defined(CONFIG_64BIT)

SYSCALL_DEFINE5(io_getevents, aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct __kernel_timespec __user *, timeout)
{
	struct timespec64	ts;
	int			ret;

	if (timeout && unlikely(get_timespec64(&ts, timeout)))
		return -EFAULT;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &ts : NULL);
	if (!ret && signal_pending(current))
		ret = -EINTR;
	return ret;
}

#endif

struct __aio_sigset {
	const sigset_t __user	*sigmask;
	size_t		sigsetsize;
};

SYSCALL_DEFINE6(io_pgetevents,
		aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct __kernel_timespec __user *, timeout,
		const struct __aio_sigset __user *, usig)
{
	struct __aio_sigset	ksig = { NULL, };
	sigset_t		ksigmask, sigsaved;
	struct timespec64	ts;
	int ret;

	if (timeout && unlikely(get_timespec64(&ts, timeout)))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;

	ret = set_user_sigmask(ksig.sigmask, &ksigmask, &sigsaved, ksig.sigsetsize);
	if (ret)
		return ret;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &ts : NULL);
	restore_user_sigmask(ksig.sigmask, &sigsaved);
	if (signal_pending(current) && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}

#if defined(CONFIG_COMPAT_32BIT_TIME) && !defined(CONFIG_64BIT)

SYSCALL_DEFINE6(io_pgetevents_time32,
		aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct old_timespec32 __user *, timeout,
		const struct __aio_sigset __user *, usig)
{
	struct __aio_sigset	ksig = { NULL, };
	sigset_t		ksigmask, sigsaved;
	struct timespec64	ts;
	int ret;

	if (timeout && unlikely(get_old_timespec32(&ts, timeout)))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;


	ret = set_user_sigmask(ksig.sigmask, &ksigmask, &sigsaved, ksig.sigsetsize);
	if (ret)
		return ret;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &ts : NULL);
	restore_user_sigmask(ksig.sigmask, &sigsaved);
	if (signal_pending(current) && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}

#endif

#if defined(CONFIG_COMPAT_32BIT_TIME)

COMPAT_SYSCALL_DEFINE5(io_getevents, compat_aio_context_t, ctx_id,
		       compat_long_t, min_nr,
		       compat_long_t, nr,
		       struct io_event __user *, events,
		       struct old_timespec32 __user *, timeout)
{
	struct timespec64 t;
	int ret;

	if (timeout && get_old_timespec32(&t, timeout))
		return -EFAULT;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &t : NULL);
	if (!ret && signal_pending(current))
		ret = -EINTR;
	return ret;
}

#endif

#ifdef CONFIG_COMPAT

struct __compat_aio_sigset {
	compat_sigset_t __user	*sigmask;
	compat_size_t		sigsetsize;
};

#if defined(CONFIG_COMPAT_32BIT_TIME)

COMPAT_SYSCALL_DEFINE6(io_pgetevents,
		compat_aio_context_t, ctx_id,
		compat_long_t, min_nr,
		compat_long_t, nr,
		struct io_event __user *, events,
		struct old_timespec32 __user *, timeout,
		const struct __compat_aio_sigset __user *, usig)
{
	struct __compat_aio_sigset ksig = { NULL, };
	sigset_t ksigmask, sigsaved;
	struct timespec64 t;
	int ret;

	if (timeout && get_old_timespec32(&t, timeout))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;

	ret = set_compat_user_sigmask(ksig.sigmask, &ksigmask, &sigsaved, ksig.sigsetsize);
	if (ret)
		return ret;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &t : NULL);
	restore_user_sigmask(ksig.sigmask, &sigsaved);
	if (signal_pending(current) && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}

#endif

COMPAT_SYSCALL_DEFINE6(io_pgetevents_time64,
		compat_aio_context_t, ctx_id,
		compat_long_t, min_nr,
		compat_long_t, nr,
		struct io_event __user *, events,
		struct __kernel_timespec __user *, timeout,
		const struct __compat_aio_sigset __user *, usig)
{
	struct __compat_aio_sigset ksig = { NULL, };
	sigset_t ksigmask, sigsaved;
	struct timespec64 t;
	int ret;

	if (timeout && get_timespec64(&t, timeout))
		return -EFAULT;

	if (usig && copy_from_user(&ksig, usig, sizeof(ksig)))
		return -EFAULT;

	ret = set_compat_user_sigmask(ksig.sigmask, &ksigmask, &sigsaved, ksig.sigsetsize);
	if (ret)
		return ret;

	ret = do_io_getevents(ctx_id, min_nr, nr, events, timeout ? &t : NULL);
	restore_user_sigmask(ksig.sigmask, &sigsaved);
	if (signal_pending(current) && !ret)
		ret = -ERESTARTNOHAND;

	return ret;
}
#endif
