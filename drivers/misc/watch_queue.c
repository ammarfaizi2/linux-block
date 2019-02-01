/* User-mappable watch queue
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "watchq: " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/watch_queue.h>

#define DEBUG_WITH_WRITE /* Allow use of write() to record notifications */

MODULE_DESCRIPTION("Watch queue");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

struct watch_type_filter {
	enum watch_notification_type type;
	__u32		subtype_filter[1];	/* Bitmask of subtypes to filter on */
	__u32		info_filter;		/* Filter on watch_notification::info */
	__u32		info_mask;		/* Mask of relevant bits in info_filter */
};

struct watch_filter {
	union {
		struct rcu_head	rcu;
		unsigned long	type_filter[2];	/* Bitmask of accepted types */
	};
	u32		nr_filters;		/* Number of filters */
	struct watch_type_filter filters[];
};

struct watch_queue {
	struct rcu_head		rcu;
	struct address_space	mapping;
	const struct cred	*cred;		/* Creds of the owner of the queue */
	struct watch_filter	*filter;
	wait_queue_head_t	waiters;
	struct hlist_head	watches;	/* Contributory watches */
	refcount_t		usage;
	spinlock_t		lock;
	bool			defunct;	/* T when queues closed */
	u8			nr_pages;	/* Size of pages[] */
	u8			flag_next;	/* Flag to apply to next item */
#ifdef DEBUG_WITH_WRITE
	u8			debug;
#endif
	u32			size;
	struct watch_queue_buffer *buffer;	/* Pointer to first record */

	/* The mappable pages.  The zeroth page holds the ring pointers. */
	struct page		**pages;
};

/**
 * post_one_notification - Post an event notification to one queue
 * @wqueue: The watch queue to add the event to.
 * @n: The notification record to post.
 *
 * Post a notification of an event into an mmap'd queue and let the user know.
 * Returns true if successful and false on failure (eg. buffer overrun or
 * userspace mucked up the ring indices).
 *
 *
 * The size of the notification should be set in n->flags & WATCH_LENGTH and
 * should be in units of sizeof(*n).
 */
static bool post_one_notification(struct watch_queue *wqueue,
				  struct watch_notification *n,
				  const struct cred *cred)
{
	struct watch_queue_buffer *buf = wqueue->buffer;
	unsigned int metalen = sizeof(buf->meta) / sizeof(buf->slots[0]);
	unsigned int size = wqueue->size, mask = size - 1;
	unsigned int len;
	unsigned int ring_tail, tail, head, used, segment, h;

	if (!buf)
		return false;

	len = (n->info & WATCH_INFO_LENGTH) >> WATCH_LENGTH_SHIFT;
	if (len == 0)
		return false;

	spin_lock(&wqueue->lock); /* Protect head pointer */

	if (wqueue->defunct ||
	    security_post_notification(wqueue->cred, cred, n) < 0)
		goto out;

	ring_tail = READ_ONCE(buf->meta.tail);
	head = READ_ONCE(buf->meta.head);
	used = head - ring_tail;

	/* Check to see if userspace mucked up the pointers */
	if (used >= size)
		goto overrun;
	tail = ring_tail & mask;
	if (tail > 0 && tail < metalen)
		goto overrun;

	h = head & mask;
	if (h >= tail) {
		/* Head is at or after tail in the buffer.  There may then be
		 * two segments: one to the end of buffer and one at the
		 * beginning of the buffer between the metadata block and the
		 * tail pointer.
		 */
		segment = size - h;
		if (len > segment) {
			/* Not enough space in the post-head segment; we need
			 * to wrap.  When wrapping, we will have to skip the
			 * metadata at the beginning of the buffer.
			 */
			if (len > tail - metalen)
				goto overrun;

			/* Fill the space at the end of the page */
			buf->slots[h].type	= WATCH_TYPE_META;
			buf->slots[h].subtype	= WATCH_META_SKIP_NOTIFICATION;
			buf->slots[h].info	= segment << WATCH_LENGTH_SHIFT;
			head += segment;
			h = 0;
			if (h >= tail)
				goto overrun;
		}
	}

	if (h == 0) {
		/* Reset and skip the header metadata */
		buf->meta.watch.type = WATCH_TYPE_META;
		buf->meta.watch.subtype = WATCH_META_SKIP_NOTIFICATION;
		buf->meta.watch.info = metalen << WATCH_LENGTH_SHIFT;
		head += metalen;
		h = metalen;
		if (h >= tail)
			goto overrun;
	}

	if (h < tail) {
		/* Head is before tail in the buffer.  There may be one segment
		 * between the two, but we may need to skip the metadata block.
		 */
		segment = tail - h;
		if (len > segment)
			goto overrun;
	}

	n->info |= wqueue->flag_next;
	wqueue->flag_next = 0;
	memcpy(buf->slots + h, n, len * sizeof(buf->slots[0]));
	head += len;

	smp_store_release(&buf->meta.head, head);
	spin_unlock(&wqueue->lock);
	if (used == 0)
		wake_up(&wqueue->waiters);
	return true;

overrun:
	wqueue->flag_next = WATCH_INFO_OVERRUN;
out:
	spin_unlock(&wqueue->lock);
	return false;
}

/*
 * Apply filter rules to a notification.
 */
static bool filter_watch_notification(const struct watch_filter *wf,
				      const struct watch_notification *n)
{
	const struct watch_type_filter *wt;
	int i;

	if (!test_bit(n->type, wf->type_filter))
		return false;

	for (i = 0; i < wf->nr_filters; i++) {
		wt = &wf->filters[i];
		if (n->type == wt->type &&
		    ((1U << n->subtype) & wt->subtype_filter[0]) &&
		    (n->info & wt->info_mask) == wt->info_filter)
			return true;
	}

	return false; /* If there is a filter, the default is to reject. */
}

/**
 * __post_watch_notification - Post an event notification
 * @wlist: The watch list to post the event to.
 * @n: The notification record to post.
 * @cred: The creds of the process that triggered the notification.
 * @id: The ID to match on the watch.
 *
 * Post a notification of an event into a set of watch queues and let the users
 * know.
 *
 * If @n is NULL then WATCH_INFO_LENGTH will be set on the next event posted.
 *
 * The size of the notification should be set in n->info & WATCH_INFO_LENGTH and
 * should be in units of sizeof(*n).
 */
void __post_watch_notification(struct watch_list *wlist,
			       struct watch_notification *n,
			       const struct cred *cred,
			       u64 id)
{
	const struct watch_filter *wf;
	struct watch_queue *wqueue;
	struct watch *watch;

	rcu_read_lock();

	hlist_for_each_entry_rcu(watch, &wlist->watchers, list_node) {
		if (watch->id != id)
			continue;
		n->info &= ~(WATCH_INFO_ID | WATCH_INFO_OVERRUN);
		n->info |= watch->info_id;

		wqueue = rcu_dereference(watch->queue);
		wf = rcu_dereference(wqueue->filter);
		if (wf && !filter_watch_notification(wf, n))
			continue;

		post_one_notification(wqueue, n, cred);
	}

	rcu_read_unlock();
}
EXPORT_SYMBOL(__post_watch_notification);

/*
 * Allow the queue to be polled.
 */
static unsigned int watch_queue_poll(struct file *file, poll_table *wait)
{
	struct watch_queue *wqueue = file->private_data;
	struct watch_queue_buffer *buf = wqueue->buffer;
	unsigned int mask = 0, head, tail;

	poll_wait(file, &wqueue->waiters, wait);

	head = READ_ONCE(buf->meta.head);
	tail = READ_ONCE(buf->meta.tail);
	if (head != tail)
		mask |= POLLIN | POLLRDNORM;
	if (head - tail > wqueue->size)
		mask |= POLLERR;
	return mask;
}

static int watch_queue_set_page_dirty(struct page *page)
{
	SetPageDirty(page);
	return 0;
}

static const struct address_space_operations watch_queue_aops = {
	.set_page_dirty	= watch_queue_set_page_dirty,
};

static int watch_queue_fault(struct vm_fault *vmf)
{
	struct watch_queue *wqueue = vmf->vma->vm_file->private_data;
	struct page *page;

	page = wqueue->pages[vmf->pgoff];
	get_page(page);
	if (!lock_page_or_retry(page, vmf->vma->vm_mm, vmf->flags)) {
		put_page(page);
		return VM_FAULT_RETRY;
	}
	vmf->page = page;
	return VM_FAULT_LOCKED;
}

static void watch_queue_map_pages(struct vm_fault *vmf,
				  pgoff_t start_pgoff, pgoff_t end_pgoff)
{
	struct watch_queue *wqueue = vmf->vma->vm_file->private_data;
	struct page *page;

	rcu_read_lock();

	do {
		page = wqueue->pages[start_pgoff];
		if (trylock_page(page)) {
			int ret;
			get_page(page);
			ret = alloc_set_pte(vmf, NULL, page);
			if (ret != 0)
				put_page(page);

			unlock_page(page);
		}
	} while (++start_pgoff < end_pgoff);

	rcu_read_unlock();
}

static const struct vm_operations_struct watch_queue_vm_ops = {
	.fault		= watch_queue_fault,
	.map_pages	= watch_queue_map_pages,
};

/*
 * Map the buffer.
 */
static int watch_queue_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct watch_queue *wqueue = file->private_data;

	if (vma->vm_pgoff != 0 ||
	    vma->vm_end - vma->vm_start > wqueue->nr_pages * PAGE_SIZE ||
	    !(pgprot_val(vma->vm_page_prot) & pgprot_val(PAGE_SHARED)))
		return -EINVAL;

	vma->vm_ops = &watch_queue_vm_ops;

	vma_interval_tree_insert(vma, &wqueue->mapping.i_mmap);
	return 0;
}

/*
 * Allocate the required number of pages.
 */
static long watch_queue_set_size(struct watch_queue *wqueue, unsigned long nr_pages)
{
	struct watch_queue_buffer *buf;
	u32 len;
	int i;

	if (nr_pages == 0 ||
	    nr_pages > 16 || /* TODO: choose a better hard limit */
	    !is_power_of_2(nr_pages))
		return -EINVAL;

	wqueue->pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!wqueue->pages)
		goto err;

	for (i = 0; i < nr_pages; i++) {
		wqueue->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!wqueue->pages[i])
			goto err_some_pages;
		wqueue->pages[i]->mapping = &wqueue->mapping;
		SetPageUptodate(wqueue->pages[i]);
	}

	buf = vmap(wqueue->pages, nr_pages, VM_MAP, PAGE_SHARED);
	if (!buf)
		goto err_some_pages;

	wqueue->buffer = buf;
	wqueue->nr_pages = nr_pages;
	wqueue->size = ((nr_pages * PAGE_SIZE) / sizeof(struct watch_notification));

	/* The first four slots in the buffer contain metadata about the ring,
	 * including the head and tail indices and mask.
	 */
	len = sizeof(buf->meta) / sizeof(buf->slots[0]);
	buf->meta.watch.info	= len << WATCH_LENGTH_SHIFT;
	buf->meta.watch.type	= WATCH_TYPE_META;
	buf->meta.watch.subtype	= WATCH_META_SKIP_NOTIFICATION;
	buf->meta.tail		= len;
	buf->meta.mask		= wqueue->size - 1;
	smp_store_release(&buf->meta.head, len);
	return 0;

err_some_pages:
	for (i--; i >= 0; i--) {
		ClearPageUptodate(wqueue->pages[i]);
		wqueue->pages[i]->mapping = NULL;
		put_page(wqueue->pages[i]);
	}

	kfree(wqueue->pages);
	wqueue->pages = NULL;
err:
	return -ENOMEM;
}

/*
 * Set the filter on a watch queue.
 */
static long watch_queue_set_filter(struct watch_queue *wqueue,
				   struct watch_notification_filter __user *_filter)
{
	struct watch_notification_type_filter *tf;
	struct watch_notification_filter filter;
	struct watch_type_filter *q;
	struct watch_filter *wfilter;
	int ret, nr_filter = 0, i;

	if (!_filter) {
		/* Remove the old filter */
		wfilter = NULL;
		goto set;
	}

	/* Grab the user's filter specification */
	if (copy_from_user(&filter, _filter, sizeof(filter)) != 0)
		return -EFAULT;
	if (filter.nr_filters == 0 ||
	    filter.nr_filters > 16 ||
	    filter.__reserved != 0)
		return -EINVAL;

	tf = memdup_user(_filter->filters, filter.nr_filters * sizeof(*tf));
	if (IS_ERR(tf))
		return PTR_ERR(tf);

	ret = -EINVAL;
	for (i = 0; i < filter.nr_filters; i++) {
		if ((tf[i].info_filter & ~tf[i].info_mask) ||
		    tf[i].info_mask & WATCH_INFO_LENGTH)
			goto err_filter;
		/* Ignore any unknown types */
		if (tf[i].type >= sizeof(wfilter->type_filter) * 8)
			continue;
		nr_filter++;
	}

	/* Now we need to build the internal filter from only the
	 * relevant user-specified filters.
	 */
	ret = -ENOMEM;
	wfilter = kzalloc(sizeof(*wfilter) + nr_filter * sizeof(*q), GFP_KERNEL);
	if (!wfilter)
		goto err_filter;
	wfilter->nr_filters = nr_filter;

	q = wfilter->filters;
	for (i = 0; i < filter.nr_filters; i++) {
		if (tf[i].type >= sizeof(wfilter->type_filter) * BITS_PER_LONG)
			continue;

		q->type			= tf[i].type;
		q->info_filter		= tf[i].info_filter;
		q->info_mask		= tf[i].info_mask;
		q->subtype_filter[0]	= tf[i].subtype_filter[0];
		__set_bit(q->type, wfilter->type_filter);
		q++;
	}

	kfree(tf);
set:
	rcu_swap_protected(wqueue->filter, wfilter, true /* inode lock */);
	if (wfilter)
		kfree_rcu(wfilter, rcu);
	return 0;

err_filter:
	kfree(tf);
	return ret;
}

/*
 * Set parameters.
 */
static long watch_queue_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct watch_queue *wqueue = file->private_data;
	long ret;

	switch (cmd) {
	case IOC_WATCH_QUEUE_SET_SIZE:
		if (wqueue->buffer)
			return -EBUSY;
		inode_lock(file_inode(file));
		ret = watch_queue_set_size(wqueue, arg);
		inode_unlock(file_inode(file));
		return ret;

	case IOC_WATCH_QUEUE_SET_FILTER:
		inode_lock(file_inode(file));
		ret = watch_queue_set_filter(
			wqueue, (struct watch_notification_filter __user *)arg);
		inode_unlock(file_inode(file));
		return ret;

	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Open the file.
 */
static int watch_queue_open(struct inode *inode, struct file *file)
{
	struct watch_queue *wqueue;

	wqueue = kzalloc(sizeof(*wqueue), GFP_KERNEL);
	if (!wqueue)
		return -ENOMEM;

	wqueue->mapping.a_ops = &watch_queue_aops;
	wqueue->mapping.i_mmap = RB_ROOT_CACHED;
	init_rwsem(&wqueue->mapping.i_mmap_rwsem);
	spin_lock_init(&wqueue->mapping.private_lock);

	refcount_set(&wqueue->usage, 1);
	spin_lock_init(&wqueue->lock);
	init_waitqueue_head(&wqueue->waiters);
	wqueue->cred = get_cred(file->f_cred);

	file->private_data = wqueue;
	return 0;
}

/**
 * put_watch_queue - Dispose of a ref on a watchqueue.
 * @wq: The watch queue to unref.
 */
void put_watch_queue(struct watch_queue *wqueue)
{
	if (refcount_dec_and_test(&wqueue->usage))
		kfree_rcu(wqueue, rcu);
}
EXPORT_SYMBOL(put_watch_queue);

/*
 * Discard a watch.
 */
static void put_watch(struct watch *watch)
{
	if (refcount_dec_and_test(&watch->usage)) {
		put_watch_queue(watch->queue);
		kfree_rcu(watch, rcu);
	}
}

/**
 * add_watch_to_object - Add a watch on an object
 * @watch: The watch to add
 *
 * @watch->queue and @watch->watch_list must have been set to point to the
 * queue to post notifications to and the watch list of the object to be
 * watched.
 *
 * The caller must pin the queue and the list both and must hold the list
 * locked against racing watch additions/removals.
 */
int add_watch_to_object(struct watch *watch)
{
	struct watch_queue *wqueue = watch->queue;
	struct watch_list *wlist = watch->watch_list;
	struct watch *w;

	hlist_for_each_entry(w, &wlist->watchers, list_node) {
		if (watch->id == w->id)
			return -EBUSY;
	}

	spin_lock(&wqueue->lock);
	refcount_inc(&wqueue->usage);
	hlist_add_head(&watch->queue_node, &wqueue->watches);
	spin_unlock(&wqueue->lock);

	hlist_add_head(&watch->list_node, &wlist->watchers);
	return 0;
}
EXPORT_SYMBOL(add_watch_to_object);

/**
 * remove_watch_from_object - Remove a watch or all watches from an object.
 * @wlist: The watch list to remove from
 * @wq: The watch queue of interest (ignored if @all is true)
 * @id: The ID of the watch to remove (ignored if @all is true)
 * @all: True to remove all objects
 *
 * Remove a specific watch or all watches from an object.  A notification is
 * sent to the watcher to tell them that this happened.
 */
int remove_watch_from_object(struct watch_list *wlist, struct watch_queue *wq,
			     u64 id, bool all)
{
	struct watch_notification n;
	struct watch_queue *wqueue;
	struct watch *watch;
	int ret = -EBADSLT;

	rcu_read_lock();

again:
	spin_lock(&wlist->lock);
	hlist_for_each_entry(watch, &wlist->watchers, list_node) {
		if (all || (watch->id == id && watch->queue == wq))
			goto found;
	}
	spin_unlock(&wlist->lock);
	goto out;

found:
	ret = 0;
	hlist_del_init_rcu(&watch->list_node);
	rcu_assign_pointer(watch->watch_list, NULL);
	spin_unlock(&wlist->lock);

	n.type = WATCH_TYPE_META;
	n.subtype = WATCH_META_REMOVAL_NOTIFICATION;
	n.info = watch->info_id | sizeof(n);

	post_one_notification(watch->queue, &n, wq ? wq->cred : NULL);

	/* We don't need the watch list lock for the next bit as RCU is
	 * protecting everything from being deallocated.
	 */
	wqueue = rcu_dereference(watch->queue);
	if (wqueue) {
		spin_lock(&wqueue->lock);

		if (!hlist_unhashed(&watch->queue_node)) {
			hlist_del_init_rcu(&watch->queue_node);
			put_watch(watch);
		}

		spin_unlock(&wqueue->lock);
	}

	if (wlist->release_watch) {
		rcu_read_unlock();
		wlist->release_watch(wlist, watch);
		rcu_read_lock();
	}
	put_watch(watch);

	if (all && !hlist_empty(&wlist->watchers))
		goto again;
out:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(remove_watch_from_object);

/*
 * Remove all the watches that are contributory to a queue.  This will
 * potentially race with removal of the watches by the destruction of the
 * objects being watched or the distribution of notifications.
 */
static void watch_queue_clear(struct watch_queue *wqueue)
{
	struct watch_list *wlist;
	struct watch *watch;
	bool release;

	rcu_read_lock();
	spin_lock(&wqueue->lock);

	/* Prevent new additions and prevent notifications from happening */
	wqueue->defunct = true;

	while (!hlist_empty(&wqueue->watches)) {
		watch = hlist_entry(wqueue->watches.first, struct watch, queue_node);
		hlist_del_init_rcu(&watch->queue_node);
		spin_unlock(&wqueue->lock);

		/* We can't do the next bit under the queue lock as we need to
		 * get the list lock - which would cause a deadlock if someone
		 * was removing from the opposite direction at the same time or
		 * posting a notification.
		 */
		wlist = rcu_dereference(watch->watch_list);
		if (wlist) {
			spin_lock(&wlist->lock);

			release = !hlist_unhashed(&watch->list_node);
			if (release) {
				hlist_del_init_rcu(&watch->list_node);
				rcu_assign_pointer(watch->watch_list, NULL);
			}

			spin_unlock(&wlist->lock);

			if (release) {
				if (wlist->release_watch) {
					rcu_read_unlock();
					/* This might need to call dput(), so
					 * we have to drop all the locks.
					 */
					wlist->release_watch(wlist, watch);
					rcu_read_lock();
				}
				put_watch(watch);
			}
		}

		put_watch(watch);
		spin_lock(&wqueue->lock);
	}

	spin_unlock(&wqueue->lock);
	rcu_read_unlock();
}

/*
 * Release the file.
 */
static int watch_queue_release(struct inode *inode, struct file *file)
{
	struct watch_queue *wqueue = file->private_data;
	int i, pgref;

	watch_queue_clear(wqueue);

	if (wqueue->pages && wqueue->pages[0])
		WARN_ON(page_ref_count(wqueue->pages[0]) != 1);

	if (wqueue->buffer)
		vfree(wqueue->buffer);
	for (i = 0; i < wqueue->nr_pages; i++) {
		ClearPageUptodate(wqueue->pages[i]);
		wqueue->pages[i]->mapping = NULL;
		pgref = page_ref_count(wqueue->pages[i]);
		WARN(pgref != 1,
		     "FREE PAGE[%d] refcount %d\n", i, page_ref_count(wqueue->pages[i]));
		__free_page(wqueue->pages[i]);
	}
	if (wqueue->filter)
		kfree_rcu(wqueue->filter, rcu);
	kfree(wqueue->pages);
	put_cred(wqueue->cred);
	put_watch_queue(wqueue);
	return 0;
}

#ifdef DEBUG_WITH_WRITE
static ssize_t watch_queue_write(struct file *file,
				 const char __user *_buf, size_t len, loff_t *pos)
{
	struct watch_notification *n;
	struct watch_queue *wqueue = file->private_data;
	ssize_t ret;

	if (!wqueue->buffer)
		return -ENOBUFS;

	if (len & ~WATCH_INFO_LENGTH || len == 0 || !_buf)
		return -EINVAL;

	n = memdup_user(_buf, len);
	if (IS_ERR(n))
		return PTR_ERR(n);

	ret = -EINVAL;
	if ((n->info & WATCH_INFO_LENGTH) != len)
		goto error;
	n->info &= (WATCH_INFO_LENGTH | WATCH_INFO_TYPE_FLAGS | WATCH_INFO_ID);

	if (post_one_notification(wqueue, n, file->f_cred))
		wqueue->debug = 0;
	else
		wqueue->debug++;
	ret = len;
	if (wqueue->debug > 20)
		ret = -EIO;

error:
	kfree(n);
	return ret;
}
#endif

static const struct file_operations watch_queue_fops = {
	.owner		= THIS_MODULE,
	.open		= watch_queue_open,
	.release	= watch_queue_release,
	.unlocked_ioctl	= watch_queue_ioctl,
	.poll		= watch_queue_poll,
	.mmap		= watch_queue_mmap,
#ifdef DEBUG_WITH_WRITE
	.write		= watch_queue_write,
#endif
	.llseek		= no_llseek,
};

/**
 * get_watch_queue - Get a watch queue from its file descriptor.
 * @fd: The fd to query.
 */
struct watch_queue *get_watch_queue(int fd)
{
	struct watch_queue *wqueue = ERR_PTR(-EBADF);
	struct fd f;

	f = fdget(fd);
	if (f.file) {
		wqueue = ERR_PTR(-EINVAL);
		if (f.file->f_op == &watch_queue_fops) {
			wqueue = f.file->private_data;
			refcount_inc(&wqueue->usage);
		}
		fdput(f);
	}

	return wqueue;
}
EXPORT_SYMBOL(get_watch_queue);

static struct miscdevice watch_queue_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "watch_queue",
	.fops	= &watch_queue_fops,
	.mode	= 0666,
};

static int __init watch_queue_init(void)
{
	int ret;

	ret = misc_register(&watch_queue_dev);
	if (ret < 0)
		pr_err("Failed to register %d\n", ret);
	return ret;
}
fs_initcall(watch_queue_init);

static void __exit watch_queue_exit(void)
{
	misc_deregister(&watch_queue_dev);
}
module_exit(watch_queue_exit);
