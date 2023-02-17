// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/pipe.c
 *
 *  Copyright (C) 1991, 1992, 1999  Linus Torvalds
 */

#include <linux/mm.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/magic.h>
#include <linux/pipe_fs_i.h>
#include <linux/uio.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/audit.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/memcontrol.h>
#include <linux/watch_queue.h>
#include <linux/sysctl.h>

#include <linux/uaccess.h>
#include <asm/ioctls.h>

#include "internal.h"
#include "pipe.h"

/*
 * Differs from PIPE_BUF in that PIPE_SIZE is the length of the actual
 * memory allocation, whereas PIPE_BUF makes atomicity guarantees.
 */
#define PIPE_SIZE		PAGE_SIZE

/*
 * New pipe buffers will be restricted to this size while the user is exceeding
 * their pipe buffer quota. The general pipe use case needs at least two
 * buffers: one for data yet to be read, and one for new data. If this is less
 * than two, then a write to a non-empty pipe may block even if the pipe is not
 * full. This can occur with GNU make jobserver or similar uses of pipes as
 * semaphores: multiple processes may be waiting to write tokens back to the
 * pipe before reading tokens: https://lore.kernel.org/lkml/1628086770.5rn8p04n6j.none@localhost/.
 *
 * Users can reduce their pipe buffers with F_SETPIPE_SZ below this at their
 * own risk, namely: pipe writes to non-full pipes may block until the pipe is
 * emptied.
 */
#define PIPE_MIN_DEF_BUFFERS 2

/*
 * The max size that a non-root user is allowed to grow the pipe. Can
 * be set by root in /proc/sys/fs/pipe-max-size
 */
static unsigned int pipe_max_size = 1048576;

/* Maximum allocatable pages per user. Hard limit is unset by default, soft
 * matches default values.
 */
static unsigned long pipe_user_pages_hard;
static unsigned long pipe_user_pages_soft = PIPE_DEF_BUFFERS * INR_OPEN_CUR;

/*
 * We use head and tail indices that aren't masked off, except at the point of
 * dereference, but rather they're allowed to wrap naturally.  This means there
 * isn't a dead spot in the buffer, but the ring has to be a power of two and
 * <= 2^31.
 * -- David Howells 2019-09-23.
 *
 * Reads with count = 0 should always return 0.
 * -- Julian Bradfield 1999-06-07.
 *
 * FIFOs and Pipes now generate SIGIO for both readers and writers.
 * -- Jeremy Elson <jelson@circlemud.org> 2001-08-16
 *
 * pipe_read & write cleanup
 * -- Manfred Spraul <manfred@colorfullife.com> 2002-05-09
 */

static void pipe_lock_nested(struct pipe_inode_info *pipe, int subclass)
{
	if (pipe->files)
		mutex_lock_nested(&pipe->mutex, subclass);
}

void pipe_lock(struct pipe_inode_info *pipe)
{
	/*
	 * pipe_lock() nests non-pipe inode locks (for writing to a file)
	 */
	pipe_lock_nested(pipe, I_MUTEX_PARENT);
}
EXPORT_SYMBOL(pipe_lock);

void pipe_unlock(struct pipe_inode_info *pipe)
{
	if (pipe->files)
		mutex_unlock(&pipe->mutex);
}
EXPORT_SYMBOL(pipe_unlock);

static inline void __pipe_lock(struct pipe_inode_info *pipe)
{
	mutex_lock_nested(&pipe->mutex, I_MUTEX_PARENT);
}

static inline void __pipe_unlock(struct pipe_inode_info *pipe)
{
	mutex_unlock(&pipe->mutex);
}

void pipe_double_lock(struct pipe_inode_info *pipe1,
		      struct pipe_inode_info *pipe2)
{
	BUG_ON(pipe1 == pipe2);

	if (pipe1 < pipe2) {
		pipe_lock_nested(pipe1, I_MUTEX_PARENT);
		pipe_lock_nested(pipe2, I_MUTEX_CHILD);
	} else {
		pipe_lock_nested(pipe2, I_MUTEX_PARENT);
		pipe_lock_nested(pipe1, I_MUTEX_CHILD);
	}
}

void wakeup_pipe_readers(struct pipe_inode_info *pipe)
{
	smp_mb();
	if (waitqueue_active(&pipe->rd_wait))
		wake_up_interruptible(&pipe->rd_wait);
	kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
}

static void anon_pipe_buf_release(struct pipe_inode_info *pipe,
				  struct pipe_buffer *buf)
{
	unsigned int i;

	for (i = 0; i < buf->nr; i++) {
		struct folio *folio = buf->bvec[i].bv_folio;

		/*
		 * If nobody else uses this page, and we don't already have a
		 * temporary page, let's keep track of it as a one-deep
		 * allocation cache. (Otherwise just release our reference to it)
		 */
		if (folio_ref_count(folio) == 1 && !pipe->spare_folio)
			pipe->spare_folio = buf->bvec[i].bv_folio;
		else
			folio_put(buf->bvec[i].bv_folio);
	}
}

static bool anon_pipe_buf_try_steal(struct pipe_inode_info *pipe,
		struct pipe_buffer *buf)
{
	struct folio *folio = buf->bvec[buf->index].bv_folio;

	if (folio_ref_count(folio) != 1)
		return false;
	memcg_kmem_uncharge_page(folio_page(folio, 0), 0);
	__folio_lock(folio);
	return true;
}

/**
 * generic_pipe_buf_try_steal - attempt to take ownership of a &pipe_buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to attempt to steal
 *
 * Description:
 *	This function attempts to steal the &struct page attached to
 *	@buf. If successful, this function returns 0 and returns with
 *	the page locked. The caller may then reuse the page for whatever
 *	he wishes; the typical use is insertion into a different file
 *	page cache.
 */
bool generic_pipe_buf_try_steal(struct pipe_inode_info *pipe,
		struct pipe_buffer *buf)
{
	struct folio *folio = buf->bvec[buf->index].bv_folio;

	/*
	 * A reference of one is golden, that means that the owner of this
	 * page is the only one holding a reference to it. lock the page
	 * and return OK.
	 */
	if (folio_ref_count(folio) == 1) {
		__folio_lock(folio);
		return true;
	}
	return false;
}
EXPORT_SYMBOL(generic_pipe_buf_try_steal);

/**
 * generic_pipe_buf_get - get a reference to a &struct pipe_buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to get a reference to
 *
 * Description:
 *	This function grabs an extra reference to @buf. It's used in
 *	the tee() system call, when we duplicate the buffers in one
 *	pipe into another.
 */
bool generic_pipe_buf_get(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	return folio_try_get(buf->bvec[buf->index].bv_folio);
}
EXPORT_SYMBOL(generic_pipe_buf_get);

/**
 * generic_pipe_buf_release - put a reference to a &struct pipe_buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to put a reference to
 *
 * Description:
 *	This function releases a reference to @buf.
 */
void generic_pipe_buf_release(struct pipe_inode_info *pipe,
			      struct pipe_buffer *buf)
{
	unsigned int i;

	for (i = 0; i < buf->nr; i++)
		folio_put(buf->bvec[i].bv_folio);
}
EXPORT_SYMBOL(generic_pipe_buf_release);

static const struct pipe_buf_operations anon_pipe_buf_ops = {
	.release	= anon_pipe_buf_release,
	.try_steal	= anon_pipe_buf_try_steal,
	.get		= generic_pipe_buf_get,
};

/**
 * pipe_query_space - Find out how much space is available in a pipe.
 * @pipe: The pipe to query
 * @len: The length requested (in) / the maximum length allowed (out)
 * @error: Where to set any error
 *
 * Checks to see if there's space available in the pipe for *@len amount of
 * data, returning the number of folios that can be added (0 if the pipe is
 * full) and shrinking *@len to fit.
 *
 * If there are no readers, it will send SIGPIPE and set -EPIPE.
 */
size_t pipe_query_space(struct pipe_inode_info *pipe, size_t *len, int *error)
{
	size_t npages;

	if (unlikely(!pipe->readers)) {
		send_sig(SIGPIPE, current, 0);
		*error = -EPIPE;
		return 0;
	}
	if (pipe->footprint >= pipe->max_footprint) {
		*error = -EAGAIN;
		return 0;
	}

	npages = pipe->max_footprint - pipe->footprint;
	*len = min_t(size_t, *len, npages * PAGE_SIZE);
	return npages;
}
EXPORT_SYMBOL(pipe_query_space);

/**
 * pipe_query_content - Find out how much data is available in a pipe.
 * @pipe: The pipe to query
 * @len: Where to return the amount of data
 *
 * Checks to see if there's content available in the pipe and if so, returns
 * the number of pages and sets *@len to the amount of bytes.
 */
size_t pipe_query_content(struct pipe_inode_info *pipe, size_t *len)
{
	*len = pipe->content;
	return pipe->footprint;
}
EXPORT_SYMBOL(pipe_query_content);

/**
 * pipe_alloc_buffer - Allocate a pipe buffer
 * @pipe: The pipe to allocate from
 * @ops: The operations to set
 * @bvcount: The number of folios we want to attach
 * @gfp: Allocation mode
 * @error: Where to place -ENOMEM if OOM occurs
 *
 * Allocate and return new pipe buffer with sufficient slots for the requested
 * number of folios.  Returns NULL if the pipe is full or we hit an OOM
 * condition.  In the OOM case, *@error will be set to -ENOMEM but left
 * untouched otherwise.
 */
struct pipe_buffer *pipe_alloc_buffer(struct pipe_inode_info *pipe,
				      const struct pipe_buf_operations *ops,
				      size_t bvcount, gfp_t gfp, int *error)
{
	struct pipe_buffer *buf;
	size_t size = struct_size(buf, bvec, bvcount);

	if (pipe_full(pipe))
		return NULL;

	if (bvcount < 1)
		bvcount = 1;

	if (pipe->spare_buffer) {
		spin_lock_irq(&pipe->rd_wait.lock);
		buf = pipe->spare_buffer;
		if (buf) {
			if (buf->max >= bvcount)
				pipe->spare_buffer = NULL;
			else
				buf = NULL;
		}
		spin_unlock_irq(&pipe->rd_wait.lock);
		if (buf) {
			bvcount = buf->max;
			memset(buf, 0, struct_size(buf, bvec, bvcount));
			buf->ops	= ops;
			buf->max	= bvcount;
			return buf;
		}
	}

	buf = kzalloc(size, gfp);
	if (!buf) {
		*error = -ENOMEM;
		return NULL;
	}

	buf->ops	= ops;
	buf->max	= bvcount;
	return buf;
}
EXPORT_SYMBOL(pipe_alloc_buffer);

/**
 * pipe_add - Pass filled data buffer into a pipe
 * @pipe: Pipe to append to
 * @buf: Buffer to add
 * @full: Set to true if the pipe is now full
 *
 * This function adds the given buffer to the tail end of the pipe.  The data
 * is contained in an array of bio_vecs providing tuples of source page, offset
 * and length.  The buffer also points to operations for managing these pages.
 *
 * The buffer is discarded without being added if there is no data in it, there
 * is no attached reader or the pipe is full.  If the buffer would overrun the
 * space in the pipe, it will be overcommitted.
 */
ssize_t pipe_add(struct pipe_inode_info *pipe, struct pipe_buffer *buf,
		 bool *full)
{
	if (buf->size == 0 || WARN_ON(pipe_full(pipe)))
		goto discard;

	spin_lock_irq(&pipe->rd_wait.lock);
	list_add_tail(&buf->queue_link, &pipe->queue);
	pipe->footprint += buf->footprint;
	*full = pipe_full(pipe);
	spin_unlock_irq(&pipe->rd_wait.lock);
	return buf->size;

discard:
	pipe_buf_release(pipe, buf);
	*full = pipe_full(pipe);
	return 0;
}
EXPORT_SYMBOL(pipe_add);

/**
 * pipe_buf_release - put a reference to a pipe_buffer
 * @pipe: the pipe that the buffer belongs to
 * @buf: the buffer to put a reference to
 */
void pipe_buf_release(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	const struct pipe_buf_operations *ops = buf->ops;

	if (ops)
		ops->release(pipe, buf);
	if (buf->index >= buf->nr) {
		spin_lock_irq(&pipe->rd_wait.lock);
		pipe->footprint -= buf->footprint;
		list_del(&buf->queue_link);
		spin_unlock_irq(&pipe->rd_wait.lock);
		kfree(buf);
	}
}

#ifdef CONFIG_WATCH_QUEUE
/**
 * pipe_set_lost_mark - Mark the pipe as having lost some data
 * @pipe: Pipe to mark
 *
 * Set a mark on a pipe to indicate that some data was lost, either due to the
 * pipe being full or failure to allocate memory.  This will cause a
 * lost-notification message to be read when the pipe gets around to the
 * current add point.
 *
 * The caller must hold pipe->rd_wait.lock and have interrupts disabled.
 */
void pipe_set_lost_mark(struct pipe_inode_info *pipe)
{
	struct pipe_buffer *buf;

	spin_lock_irq(&pipe->rd_wait.lock);
	if (pipe_empty(pipe)) {
		pipe->note_loss = true;
	} else {
		buf = list_last_entry(&pipe->queue, struct pipe_buffer, queue_link);
		buf->flags |= PIPE_BUF_FLAG_LOSS;
	}
	spin_unlock_irq(&pipe->rd_wait.lock);
}
#endif

/* Done while waiting without holding the pipe lock - thus the READ_ONCE() */
static inline bool pipe_readable(const struct pipe_inode_info *pipe)
{
	return !pipe_empty(pipe) || !READ_ONCE(pipe->writers);
}

/*
 * Deal with the consumption of some data from a pipe buffer.  Returns true if
 * we've consumed all the data.
 */
bool pipe_consume(struct pipe_inode_info *pipe, struct pipe_buffer *buf, size_t consumed)
{
	if (WARN_ON_ONCE(consumed > buf->size))
		consumed = buf->size;
	buf->size -= consumed;

	do {
		struct bio_vec *bv = &buf->bvec[buf->index];
		size_t part = min_t(size_t, consumed, bv->bv_len);

		bv->bv_len -= part;
		bv->bv_offset += part;
		consumed -= part;

		if (bv->bv_len > 0)
			break;

		buf->ops->release(pipe, buf);
		buf->index++;
	} while (consumed > 0);

	return buf->size == 0;
}

/*
 * Copy data from a pipe buffer into an iterator, confirming the pages in the
 * buffer as we use them and releasing them when we've used them.
 */
static ssize_t pipe_copy_buf_to_iter(struct pipe_inode_info *pipe,
				     struct pipe_buffer *buf,
				     struct iov_iter *iter)
{
	size_t part, n, copied = 0;
	int ret = 0;

	while (buf->size) {
		struct bio_vec *bv = &buf->bvec[buf->nr];

		if (buf->nr_confirmed <= buf->index) {
			ret = pipe_buf_confirm(pipe, buf);
			if (ret < 0)
				break;
		}

		part = min_t(size_t, bv->bv_len, iov_iter_count(iter));
		n = copy_folio_to_iter(bv->bv_folio, bv->bv_offset, part, iter);
		if (unlikely(n < part)) {
			ret = -EFAULT;
			break;
		}

		copied += n;
		pipe_consume(pipe, buf, n);
	}

	return copied ?: ret;
}

static ssize_t pipe_read(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *filp = iocb->ki_filp;
	struct pipe_inode_info *pipe = filp->private_data;
	bool was_full, wake_next_reader = false, stop;
	ssize_t copied = 0, ret = 0;

	/* Null read succeeds. */
	if (unlikely(!iov_iter_count(iter)))
		return 0;

	__pipe_lock(pipe);

	/*
	 * We only wake up writers if the pipe was full when we started
	 * reading in order to avoid unnecessary wakeups.
	 *
	 * But when we do wake up writers, we do so using a sync wakeup
	 * (WF_SYNC), because we want them to get going and generate more
	 * data for us.
	 */
	was_full = pipe_full(pipe);
	for (;;) {
		struct pipe_buffer *buf;

#ifdef CONFIG_WATCH_QUEUE
		if (pipe->note_loss) {
			struct watch_notification n;

			if (iov_iter_count(iter) < 8) {
				ret = -ENOBUFS;
				break;
			}

			n.type = WATCH_TYPE_META;
			n.subtype = WATCH_META_LOSS_NOTIFICATION;
			n.info = watch_sizeof(n);
			if (copy_to_iter(&n, sizeof(n), iter) != sizeof(n)) {
				if (ret == 0)
					ret = -EFAULT;
				break;
			}
			copied += sizeof(n);
			pipe->note_loss = false;
		}
#endif

		buf = pipe_head_buf(pipe);
		if (buf) {
			if (buf->ops->copy_to_iter)
				ret = buf->ops->copy_to_iter(pipe, buf, iter);
			else
				ret = pipe_copy_buf_to_iter(pipe, buf, iter);
			if (ret > 0)
				copied += ret;

			/* Was it a packet buffer? Clean up and exit */
			stop = buf->flags & PIPE_BUF_FLAG_PACKET;
			if (stop)
				buf->size = 0;

			if (!buf->size) {
#ifdef CONFIG_WATCH_QUEUE
				if (buf->flags & PIPE_BUF_FLAG_LOSS)
					pipe->note_loss = true;
#endif
				pipe_buf_release(pipe, buf);
			}

			if (!iov_iter_count(iter))
				break;	/* common path: read succeeded */
			if (!pipe_empty(pipe))	/* More to do? */
				continue;
		}

		if (!pipe->writers)
			break;
		if (ret)
			break;
		if (filp->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		__pipe_unlock(pipe);

		/*
		 * We only get here if we didn't actually read anything.
		 *
		 * However, we could have seen (and removed) a zero-sized
		 * pipe buffer, and might have made space in the buffers
		 * that way.
		 *
		 * You can't make zero-sized pipe buffers by doing an empty
		 * write (not even in packet mode), but they can happen if
		 * the writer gets an EFAULT when trying to fill a buffer
		 * that already got allocated and inserted in the buffer
		 * array.
		 *
		 * So we still need to wake up any pending writers in the
		 * _very_ unlikely case that the pipe was full, but we got
		 * no data.
		 */
		if (unlikely(was_full))
			wake_up_interruptible_sync_poll(&pipe->wr_wait, EPOLLOUT | EPOLLWRNORM);
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);

		/*
		 * But because we didn't read anything, at this point we can
		 * just return directly with -ERESTARTSYS if we're interrupted,
		 * since we've done any required wakeups and there's no need
		 * to mark anything accessed. And we've dropped the lock.
		 */
		if (wait_event_interruptible_exclusive(pipe->rd_wait, pipe_readable(pipe)) < 0)
			return -ERESTARTSYS;

		__pipe_lock(pipe);
		was_full = pipe_full(pipe);
		wake_next_reader = true;
	}
	if (pipe_empty(pipe))
		wake_next_reader = false;
	__pipe_unlock(pipe);

	if (was_full)
		wake_up_interruptible_sync_poll(&pipe->wr_wait, EPOLLOUT | EPOLLWRNORM);
	if (wake_next_reader)
		wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN | EPOLLRDNORM);
	kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
	if (ret > 0)
		file_accessed(filp);
	return copied ?: ret;
}

static inline int is_packetized(struct file *file)
{
	return (file->f_flags & O_DIRECT) != 0;
}

/* Done while waiting without holding the pipe lock - thus the READ_ONCE() */
static inline bool pipe_writable(const struct pipe_inode_info *pipe)
{
	return !pipe_full(pipe) || !READ_ONCE(pipe->readers);
}

/*
 * copy_iter_to_folio - Copy data from an iterator into a folio
 * @iter: Source iterator
 * @folio: Destination folio
 * @offset: Offset within the folio to start writing
 * @len: Amount to copy
 */
static ssize_t copy_iter_to_folio(struct iov_iter *iter, struct folio *folio,
				  size_t offset, size_t len)
{
	size_t copied = 0;

	while (len > 0 && iov_iter_count(iter) > 0) {
		size_t pnum = offset / PAGE_SIZE;
		size_t poff = offset & ~PAGE_MASK;
		size_t part = min3(len, PAGE_SIZE - offset, iov_iter_count(iter));
		size_t n;

		n = copy_page_from_iter(folio_page(folio, pnum), poff, part, iter);
		offset += n;
		copied += n;
		if (n < part)
			return copied ?: -EFAULT;
	}

	return copied;
}

static ssize_t pipe_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *filp = iocb->ki_filp;
	struct pipe_inode_info *pipe = filp->private_data;
	size_t total_len = iov_iter_count(from);
	ssize_t written = 0, chars;
	bool was_empty = false;
	bool wake_next_writer = false;
	bool full = pipe_full(pipe);
	int ret = 0;

	/* Null write succeeds. */
	if (unlikely(total_len == 0))
		return 0;

	__pipe_lock(pipe);

	if (!pipe->readers) {
		send_sig(SIGPIPE, current, 0);
		ret = -EPIPE;
		goto out;
	}

#ifdef CONFIG_WATCH_QUEUE
	if (pipe->watch_queue) {
		ret = -EXDEV;
		goto out;
	}
#endif

	/*
	 * If it wasn't empty we try to merge new data into
	 * the last buffer.
	 *
	 * That naturally merges small writes, but it also
	 * page-aligns the rest of the writes for large writes
	 * spanning multiple pages.
	 */
	was_empty = pipe_empty(pipe);
	chars = total_len & (PAGE_SIZE-1);
	if (chars && !was_empty) {
		struct pipe_buffer *buf =
			list_last_entry(&pipe->queue,
					struct pipe_buffer, queue_link);
		struct bio_vec *bv = &buf->bvec[0];
		size_t offset = bv->bv_offset + bv->bv_len;

		if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
		    offset + chars <= folio_size(bv->bv_folio)) {
			ret = pipe_buf_confirm(pipe, buf);
			if (ret)
				goto out;

			ret = copy_iter_to_folio(from, bv->bv_folio, offset, chars);
			if (unlikely(ret < chars)) {
				ret = -EFAULT;
				goto out;
			}

			buf->size += ret;
			if (!iov_iter_count(from))
				goto out;
		}
	}

	for (;;) {
		if (!pipe->readers) {
			send_sig(SIGPIPE, current, 0);
			ret = -EPIPE;
			break;
		}

		if (!full) {
			struct pipe_buffer *buf;
			struct folio *folio = pipe->spare_folio;
			ssize_t copied;
			size_t part;

			buf = pipe_alloc_buffer(pipe, &anon_pipe_buf_ops,
						1, GFP_KERNEL, &ret);
			if (!buf)
				break;

			folio = pipe->spare_folio;
			if (!folio) {
				folio = folio_alloc(GFP_HIGHUSER | __GFP_ACCOUNT, 0);
				if (unlikely(!folio)) {
					ret = -ENOMEM;
					break;
				}
			} else {
				pipe->spare_folio = NULL;
			}

			buf->bvec[0].bv_folio	= folio;
			buf->bvec[0].bv_offset	= 0;
			buf->bvec[0].bv_len	= 0;
			buf->nr = 1;
			buf->footprint += folio_nr_pages(folio);

			if (is_packetized(filp))
				buf->flags = PIPE_BUF_FLAG_PACKET;
			else
				buf->flags = PIPE_BUF_FLAG_CAN_MERGE;

			part = min(iov_iter_count(from), folio_size(folio));
			copied = copy_iter_to_folio(from, folio, 0, folio_size(folio));
			if (unlikely(copied < part)) {
				if (!ret)
					ret = -EFAULT;
				break;
			}
			ret += copied;
			buf->bvec[0].bv_len += copied;
			buf->size += copied;
			ret = pipe_add(pipe, buf, &full);

			if (!iov_iter_count(from))
				break;
		}

		if (!full)
			continue;

		/* Wait for buffer space to become available. */
		if (filp->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		/*
		 * We're going to release the pipe lock and wait for more
		 * space. We wake up any readers if necessary, and then
		 * after waiting we need to re-check whether the pipe
		 * become empty while we dropped the lock.
		 */
		__pipe_unlock(pipe);
		if (was_empty)
			wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN | EPOLLRDNORM);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
		wait_event_interruptible_exclusive(pipe->wr_wait, pipe_writable(pipe));
		__pipe_lock(pipe);
		was_empty = pipe_empty(pipe);
		wake_next_writer = true;
		full = pipe_full(pipe);
	}
out:
	if (pipe_full(pipe))
		wake_next_writer = false;
	__pipe_unlock(pipe);

	/*
	 * If we do do a wakeup event, we do a 'sync' wakeup, because we
	 * want the reader to start processing things asap, rather than
	 * leave the data pending.
	 *
	 * This is particularly important for small writes, because of
	 * how (for example) the GNU make jobserver uses small writes to
	 * wake up pending jobs
	 *
	 * Epoll nonsensically wants a wakeup whether the pipe
	 * was already empty or not.
	 */
	if (was_empty || pipe->poll_usage)
		wake_up_interruptible_sync_poll(&pipe->rd_wait, EPOLLIN | EPOLLRDNORM);
	kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
	if (wake_next_writer)
		wake_up_interruptible_sync_poll(&pipe->wr_wait, EPOLLOUT | EPOLLWRNORM);
	if (written && sb_start_write_trylock(file_inode(filp)->i_sb)) {
		ret = file_update_time(filp);
		if (ret)
			written = ret;
		sb_end_write(file_inode(filp)->i_sb);
	}
	return written ?: ret;
}

static long pipe_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct pipe_inode_info *pipe = filp->private_data;
	struct pipe_buffer *buf;
	unsigned int count;

	switch (cmd) {
	case FIONREAD:
		__pipe_lock(pipe);
		count = 0;
		list_for_each_entry(buf, &pipe->queue, queue_link) {
			count += buf->size;
		}
		__pipe_unlock(pipe);

		return put_user(count, (int __user *)arg);

#ifdef CONFIG_WATCH_QUEUE
	case IOC_WATCH_QUEUE_SET_SIZE:
		return 0; /* Does nothing for the moment. */

	case IOC_WATCH_QUEUE_SET_FILTER:
		return watch_queue_set_filter(
			pipe, (struct watch_notification_filter __user *)arg);
#endif

	default:
		return -ENOIOCTLCMD;
	}
}

/* No kernel lock held - fine */
static __poll_t
pipe_poll(struct file *filp, poll_table *wait)
{
	__poll_t mask;
	struct pipe_inode_info *pipe = filp->private_data;

	/* Epoll has some historical nasty semantics, this enables them */
	WRITE_ONCE(pipe->poll_usage, true);

	/*
	 * Reading pipe state only -- no need for acquiring the semaphore.
	 *
	 * But because this is racy, the code has to add the
	 * entry to the poll table _first_ ..
	 */
	if (filp->f_mode & FMODE_READ)
		poll_wait(filp, &pipe->rd_wait, wait);
	if (filp->f_mode & FMODE_WRITE)
		poll_wait(filp, &pipe->wr_wait, wait);

	/*
	 * .. and only then can you do the racy tests. That way,
	 * if something changes and you got it wrong, the poll
	 * table entry will wake you up and fix it.
	 */
	mask = 0;
	if (filp->f_mode & FMODE_READ) {
		if (!pipe_empty(pipe))
			mask |= EPOLLIN | EPOLLRDNORM;
		if (!pipe->writers && filp->f_version != pipe->w_counter)
			mask |= EPOLLHUP;
	}

	if (filp->f_mode & FMODE_WRITE) {
		if (!pipe_full(pipe))
			mask |= EPOLLOUT | EPOLLWRNORM;
		/*
		 * Most Unices do not set EPOLLERR for FIFOs but on Linux they
		 * behave exactly like pipes for poll().
		 */
		if (!pipe->readers)
			mask |= EPOLLERR;
	}

	return mask;
}

static void put_pipe_info(struct inode *inode, struct pipe_inode_info *pipe)
{
	int kill = 0;

	spin_lock(&inode->i_lock);
	if (!--pipe->files) {
		inode->i_pipe = NULL;
		kill = 1;
	}
	spin_unlock(&inode->i_lock);

	if (kill)
		free_pipe_info(pipe);
}

static int
pipe_release(struct inode *inode, struct file *file)
{
	struct pipe_inode_info *pipe = file->private_data;

	__pipe_lock(pipe);
	if (file->f_mode & FMODE_READ)
		pipe->readers--;
	if (file->f_mode & FMODE_WRITE)
		pipe->writers--;

	/* Was that the last reader or writer, but not the other side? */
	if (!pipe->readers != !pipe->writers) {
		wake_up_interruptible_all(&pipe->rd_wait);
		wake_up_interruptible_all(&pipe->wr_wait);
		kill_fasync(&pipe->fasync_readers, SIGIO, POLL_IN);
		kill_fasync(&pipe->fasync_writers, SIGIO, POLL_OUT);
	}
	__pipe_unlock(pipe);

	put_pipe_info(inode, pipe);
	return 0;
}

static int
pipe_fasync(int fd, struct file *filp, int on)
{
	struct pipe_inode_info *pipe = filp->private_data;
	int retval = 0;

	__pipe_lock(pipe);
	if (filp->f_mode & FMODE_READ)
		retval = fasync_helper(fd, filp, on, &pipe->fasync_readers);
	if ((filp->f_mode & FMODE_WRITE) && retval >= 0) {
		retval = fasync_helper(fd, filp, on, &pipe->fasync_writers);
		if (retval < 0 && (filp->f_mode & FMODE_READ))
			/* this can happen only if on == T */
			fasync_helper(-1, filp, 0, &pipe->fasync_readers);
	}
	__pipe_unlock(pipe);
	return retval;
}

static unsigned long account_pipe_buffers(struct user_struct *user,
					  unsigned long old, unsigned long new)
{
	return atomic_long_add_return(new - old, &user->pipe_bufs);
}

static bool too_many_pipe_buffers_soft(unsigned long user_bufs)
{
	unsigned long soft_limit = READ_ONCE(pipe_user_pages_soft);

	return soft_limit && user_bufs > soft_limit;
}

static bool too_many_pipe_buffers_hard(unsigned long user_bufs)
{
	unsigned long hard_limit = READ_ONCE(pipe_user_pages_hard);

	return hard_limit && user_bufs > hard_limit;
}

static bool pipe_is_unprivileged_user(void)
{
	return !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN);
}

struct pipe_inode_info *alloc_pipe_info(void)
{
	struct pipe_inode_info *pipe;
	struct user_struct *user = get_current_user();
	size_t limit = PIPE_DEF_BUFFERS, user_bufs;
	size_t sys = min_t(size_t, DIV_ROUND_UP(READ_ONCE(pipe_max_size), PAGE_SIZE), 1);

	pipe = kzalloc(sizeof(struct pipe_inode_info), GFP_KERNEL_ACCOUNT);
	if (pipe == NULL)
		goto out_free_uid;

	if (limit > sys && !capable(CAP_SYS_RESOURCE))
		limit = sys;

	user_bufs = account_pipe_buffers(user, 0, limit);

	if (too_many_pipe_buffers_soft(user_bufs) && pipe_is_unprivileged_user()) {
		user_bufs = account_pipe_buffers(user, limit, PIPE_MIN_DEF_BUFFERS);
		limit = PIPE_MIN_DEF_BUFFERS;
	}

	if (too_many_pipe_buffers_hard(user_bufs) && pipe_is_unprivileged_user())
		goto out_revert_acct;

	INIT_LIST_HEAD(&pipe->queue);
	init_waitqueue_head(&pipe->rd_wait);
	init_waitqueue_head(&pipe->wr_wait);
	pipe->r_counter = pipe->w_counter = 1;
	pipe->max_footprint = limit;
	pipe->user = user;
	mutex_init(&pipe->mutex);
	return pipe;

out_revert_acct:
	(void) account_pipe_buffers(user, limit, 0);
	kfree(pipe);
out_free_uid:
	free_uid(user);
	return NULL;
}

void free_pipe_info(struct pipe_inode_info *pipe)
{
	struct pipe_buffer *buf;

#ifdef CONFIG_WATCH_QUEUE
	if (pipe->watch_queue)
		watch_queue_clear(pipe->watch_queue);
#endif

	(void) account_pipe_buffers(pipe->user, pipe->footprint, 0);
	free_uid(pipe->user);
	while ((buf = list_first_entry_or_null(
			&pipe->queue, struct pipe_buffer, queue_link))) {
		pipe_buf_release(pipe, buf);
	}
#ifdef CONFIG_WATCH_QUEUE
	if (pipe->watch_queue)
		put_watch_queue(pipe->watch_queue);
#endif
	if (pipe->spare_folio)
		folio_put(pipe->spare_folio);
	kfree(pipe->spare_buffer);
	kfree(pipe);
}

static struct vfsmount *pipe_mnt __read_mostly;

/*
 * pipefs_dname() is called from d_path().
 */
static char *pipefs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(buffer, buflen, "pipe:[%lu]",
				d_inode(dentry)->i_ino);
}

static const struct dentry_operations pipefs_dentry_operations = {
	.d_dname	= pipefs_dname,
};

static struct inode * get_pipe_inode(void)
{
	struct inode *inode = new_inode_pseudo(pipe_mnt->mnt_sb);
	struct pipe_inode_info *pipe;

	if (!inode)
		goto fail_inode;

	inode->i_ino = get_next_ino();

	pipe = alloc_pipe_info();
	if (!pipe)
		goto fail_iput;

	inode->i_pipe = pipe;
	pipe->files = 2;
	pipe->readers = pipe->writers = 1;
	inode->i_fop = &pipefifo_fops;

	/*
	 * Mark the inode dirty from the very beginning,
	 * that way it will never be moved to the dirty
	 * list because "mark_inode_dirty()" will think
	 * that it already _is_ on the dirty list.
	 */
	inode->i_state = I_DIRTY;
	inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

	return inode;

fail_iput:
	iput(inode);

fail_inode:
	return NULL;
}

int create_pipe_files(struct file **res, int flags)
{
	struct inode *inode = get_pipe_inode();
	struct file *f;
	int error;

	if (!inode)
		return -ENFILE;

	if (flags & O_NOTIFICATION_PIPE) {
		error = watch_queue_init(inode->i_pipe);
		if (error) {
			free_pipe_info(inode->i_pipe);
			iput(inode);
			return error;
		}
	}

	f = alloc_file_pseudo(inode, pipe_mnt, "",
				O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT)),
				&pipefifo_fops);
	if (IS_ERR(f)) {
		free_pipe_info(inode->i_pipe);
		iput(inode);
		return PTR_ERR(f);
	}

	f->private_data = inode->i_pipe;

	res[0] = alloc_file_clone(f, O_RDONLY | (flags & O_NONBLOCK),
				  &pipefifo_fops);
	if (IS_ERR(res[0])) {
		put_pipe_info(inode, inode->i_pipe);
		fput(f);
		return PTR_ERR(res[0]);
	}
	res[0]->private_data = inode->i_pipe;
	res[1] = f;
	stream_open(inode, res[0]);
	stream_open(inode, res[1]);
	return 0;
}

static int __do_pipe_flags(int *fd, struct file **files, int flags)
{
	int error;
	int fdw, fdr;

	if (flags & ~(O_CLOEXEC | O_NONBLOCK | O_DIRECT | O_NOTIFICATION_PIPE))
		return -EINVAL;

	error = create_pipe_files(files, flags);
	if (error)
		return error;

	error = get_unused_fd_flags(flags);
	if (error < 0)
		goto err_read_pipe;
	fdr = error;

	error = get_unused_fd_flags(flags);
	if (error < 0)
		goto err_fdr;
	fdw = error;

	audit_fd_pair(fdr, fdw);
	fd[0] = fdr;
	fd[1] = fdw;
	return 0;

 err_fdr:
	put_unused_fd(fdr);
 err_read_pipe:
	fput(files[0]);
	fput(files[1]);
	return error;
}

int do_pipe_flags(int *fd, int flags)
{
	struct file *files[2];
	int error = __do_pipe_flags(fd, files, flags);
	if (!error) {
		fd_install(fd[0], files[0]);
		fd_install(fd[1], files[1]);
	}
	return error;
}

/*
 * sys_pipe() is the normal C calling standard for creating
 * a pipe. It's not the way Unix traditionally does this, though.
 */
static int do_pipe2(int __user *fildes, int flags)
{
	struct file *files[2];
	int fd[2];
	int error;

	error = __do_pipe_flags(fd, files, flags);
	if (!error) {
		if (unlikely(copy_to_user(fildes, fd, sizeof(fd)))) {
			fput(files[0]);
			fput(files[1]);
			put_unused_fd(fd[0]);
			put_unused_fd(fd[1]);
			error = -EFAULT;
		} else {
			fd_install(fd[0], files[0]);
			fd_install(fd[1], files[1]);
		}
	}
	return error;
}

SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
{
	return do_pipe2(fildes, flags);
}

SYSCALL_DEFINE1(pipe, int __user *, fildes)
{
	return do_pipe2(fildes, 0);
}

/*
 * This is the stupid "wait for pipe to be readable or writable"
 * model.
 *
 * See pipe_read/write() for the proper kind of exclusive wait,
 * but that requires that we wake up any other readers/writers
 * if we then do not end up reading everything (ie the whole
 * "wake_next_reader/writer" logic in pipe_read/write()).
 */
void pipe_wait_readable(struct pipe_inode_info *pipe)
{
	pipe_unlock(pipe);
	wait_event_interruptible(pipe->rd_wait, pipe_readable(pipe));
	pipe_lock(pipe);
}

void pipe_wait_writable(struct pipe_inode_info *pipe)
{
	pipe_unlock(pipe);
	wait_event_interruptible(pipe->wr_wait, pipe_writable(pipe));
	pipe_lock(pipe);
}

/*
 * This depends on both the wait (here) and the wakeup (wake_up_partner)
 * holding the pipe lock, so "*cnt" is stable and we know a wakeup cannot
 * race with the count check and waitqueue prep.
 *
 * Normally in order to avoid races, you'd do the prepare_to_wait() first,
 * then check the condition you're waiting for, and only then sleep. But
 * because of the pipe lock, we can check the condition before being on
 * the wait queue.
 *
 * We use the 'rd_wait' waitqueue for pipe partner waiting.
 */
static int wait_for_partner(struct pipe_inode_info *pipe, unsigned int *cnt)
{
	DEFINE_WAIT(rdwait);
	int cur = *cnt;

	while (cur == *cnt) {
		prepare_to_wait(&pipe->rd_wait, &rdwait, TASK_INTERRUPTIBLE);
		pipe_unlock(pipe);
		schedule();
		finish_wait(&pipe->rd_wait, &rdwait);
		pipe_lock(pipe);
		if (signal_pending(current))
			break;
	}
	return cur == *cnt ? -ERESTARTSYS : 0;
}

static void wake_up_partner(struct pipe_inode_info *pipe)
{
	wake_up_interruptible_all(&pipe->rd_wait);
}

static int fifo_open(struct inode *inode, struct file *filp)
{
	struct pipe_inode_info *pipe;
	bool is_pipe = inode->i_sb->s_magic == PIPEFS_MAGIC;
	int ret;

	filp->f_version = 0;

	spin_lock(&inode->i_lock);
	if (inode->i_pipe) {
		pipe = inode->i_pipe;
		pipe->files++;
		spin_unlock(&inode->i_lock);
	} else {
		spin_unlock(&inode->i_lock);
		pipe = alloc_pipe_info();
		if (!pipe)
			return -ENOMEM;
		pipe->files = 1;
		spin_lock(&inode->i_lock);
		if (unlikely(inode->i_pipe)) {
			inode->i_pipe->files++;
			spin_unlock(&inode->i_lock);
			free_pipe_info(pipe);
			pipe = inode->i_pipe;
		} else {
			inode->i_pipe = pipe;
			spin_unlock(&inode->i_lock);
		}
	}
	filp->private_data = pipe;
	/* OK, we have a pipe and it's pinned down */

	__pipe_lock(pipe);

	/* We can only do regular read/write on fifos */
	stream_open(inode, filp);

	switch (filp->f_mode & (FMODE_READ | FMODE_WRITE)) {
	case FMODE_READ:
	/*
	 *  O_RDONLY
	 *  POSIX.1 says that O_NONBLOCK means return with the FIFO
	 *  opened, even when there is no process writing the FIFO.
	 */
		pipe->r_counter++;
		if (pipe->readers++ == 0)
			wake_up_partner(pipe);

		if (!is_pipe && !pipe->writers) {
			if ((filp->f_flags & O_NONBLOCK)) {
				/* suppress EPOLLHUP until we have
				 * seen a writer */
				filp->f_version = pipe->w_counter;
			} else {
				if (wait_for_partner(pipe, &pipe->w_counter))
					goto err_rd;
			}
		}
		break;

	case FMODE_WRITE:
	/*
	 *  O_WRONLY
	 *  POSIX.1 says that O_NONBLOCK means return -1 with
	 *  errno=ENXIO when there is no process reading the FIFO.
	 */
		ret = -ENXIO;
		if (!is_pipe && (filp->f_flags & O_NONBLOCK) && !pipe->readers)
			goto err;

		pipe->w_counter++;
		if (!pipe->writers++)
			wake_up_partner(pipe);

		if (!is_pipe && !pipe->readers) {
			if (wait_for_partner(pipe, &pipe->r_counter))
				goto err_wr;
		}
		break;

	case FMODE_READ | FMODE_WRITE:
	/*
	 *  O_RDWR
	 *  POSIX.1 leaves this case "undefined" when O_NONBLOCK is set.
	 *  This implementation will NEVER block on a O_RDWR open, since
	 *  the process can at least talk to itself.
	 */

		pipe->readers++;
		pipe->writers++;
		pipe->r_counter++;
		pipe->w_counter++;
		if (pipe->readers == 1 || pipe->writers == 1)
			wake_up_partner(pipe);
		break;

	default:
		ret = -EINVAL;
		goto err;
	}

	/* Ok! */
	__pipe_unlock(pipe);
	return 0;

err_rd:
	if (!--pipe->readers)
		wake_up_interruptible(&pipe->wr_wait);
	ret = -ERESTARTSYS;
	goto err;

err_wr:
	if (!--pipe->writers)
		wake_up_interruptible_all(&pipe->rd_wait);
	ret = -ERESTARTSYS;
	goto err;

err:
	__pipe_unlock(pipe);

	put_pipe_info(inode, pipe);
	return ret;
}

const struct file_operations pipefifo_fops = {
	.open		= fifo_open,
	.llseek		= no_llseek,
	.read_iter	= pipe_read,
	.write_iter	= pipe_write,
	.poll		= pipe_poll,
	.unlocked_ioctl	= pipe_ioctl,
	.release	= pipe_release,
	.fasync		= pipe_fasync,
	.splice_write	= iter_file_splice_write,
};

/*
 * Change the limit on the amount of data allowed into a pipe. Returns the pipe
 * size if successful, or return -ERROR on error.
 */
static long pipe_set_size(struct pipe_inode_info *pipe, unsigned long arg)
{
	unsigned long user_bufs;
	size_t limit;
	size_t sys = min_t(size_t, DIV_ROUND_UP(pipe_max_size, PAGE_SIZE), 1);
	long ret = 0;

#ifdef CONFIG_WATCH_QUEUE
	if (pipe->watch_queue)
		return -EBUSY;
#endif

	limit = DIV_ROUND_UP(arg, PAGE_SIZE);
	limit = min_t(size_t, limit, 1);

	/*
	 * If trying to increase the pipe capacity, check that an unprivileged
	 * user is not trying to exceed various limits (soft limit check here,
	 * hard limit check just below).  Decreasing the pipe capacity is
	 * always permitted, even if the user is currently over a limit.
	 */
	if (limit > pipe->max_footprint &&
	    limit > sys && !capable(CAP_SYS_RESOURCE))
		return -EPERM;

	user_bufs = account_pipe_buffers(pipe->user, pipe->max_footprint, limit);

	if (limit > pipe->max_footprint &&
	    (too_many_pipe_buffers_hard(user_bufs) ||
	     too_many_pipe_buffers_soft(user_bufs)) &&
	    pipe_is_unprivileged_user()) {
		ret = -EPERM;
		goto out_revert_acct;
	}

	pipe->max_footprint = limit;
	return pipe->max_footprint * PAGE_SIZE;

out_revert_acct:
	(void) account_pipe_buffers(pipe->user, limit, pipe->max_footprint);
	return ret;
}

/*
 * Note that i_pipe and i_cdev share the same location, so checking ->i_pipe is
 * not enough to verify that this is a pipe.
 */
struct pipe_inode_info *get_pipe_info(struct file *file, bool for_splice)
{
	struct pipe_inode_info *pipe = file->private_data;

	if (file->f_op != &pipefifo_fops || !pipe)
		return NULL;
#ifdef CONFIG_WATCH_QUEUE
	if (for_splice && pipe->watch_queue)
		return NULL;
#endif
	return pipe;
}

long pipe_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pipe_inode_info *pipe;
	long ret;

	pipe = get_pipe_info(file, false);
	if (!pipe)
		return -EBADF;

	__pipe_lock(pipe);

	switch (cmd) {
	case F_SETPIPE_SZ:
		ret = pipe_set_size(pipe, arg);
		break;
	case F_GETPIPE_SZ:
		ret = pipe->max_footprint;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	__pipe_unlock(pipe);
	return ret;
}

static const struct super_operations pipefs_ops = {
	.destroy_inode = free_inode_nonrcu,
	.statfs = simple_statfs,
};

/*
 * pipefs should _never_ be mounted by userland - too much of security hassle,
 * no real gain from having the whole whorehouse mounted. So we don't need
 * any operations on the root directory. However, we need a non-trivial
 * d_name - pipe: will go nicely and kill the special-casing in procfs.
 */

static int pipefs_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, PIPEFS_MAGIC);
	if (!ctx)
		return -ENOMEM;
	ctx->ops = &pipefs_ops;
	ctx->dops = &pipefs_dentry_operations;
	return 0;
}

static struct file_system_type pipe_fs_type = {
	.name		= "pipefs",
	.init_fs_context = pipefs_init_fs_context,
	.kill_sb	= kill_anon_super,
};

#ifdef CONFIG_SYSCTL
static int do_proc_dopipe_max_size_conv(unsigned long *lvalp,
					unsigned int *valp,
					int write, void *data)
{
	if (write) {
		unsigned int val;

		val = round_up(*lvalp, PAGE_SIZE);
		if (val == 0)
			return -EINVAL;

		*valp = val;
	} else {
		unsigned int val = *valp;
		*lvalp = (unsigned long) val;
	}

	return 0;
}

static int proc_dopipe_max_size(struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	return do_proc_douintvec(table, write, buffer, lenp, ppos,
				 do_proc_dopipe_max_size_conv, NULL);
}

static struct ctl_table fs_pipe_sysctls[] = {
	{
		.procname	= "pipe-max-size",
		.data		= &pipe_max_size,
		.maxlen		= sizeof(pipe_max_size),
		.mode		= 0644,
		.proc_handler	= proc_dopipe_max_size,
	},
	{
		.procname	= "pipe-user-pages-hard",
		.data		= &pipe_user_pages_hard,
		.maxlen		= sizeof(pipe_user_pages_hard),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{
		.procname	= "pipe-user-pages-soft",
		.data		= &pipe_user_pages_soft,
		.maxlen		= sizeof(pipe_user_pages_soft),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
	},
	{ }
};
#endif

static int __init init_pipe_fs(void)
{
	int err = register_filesystem(&pipe_fs_type);

	if (!err) {
		pipe_mnt = kern_mount(&pipe_fs_type);
		if (IS_ERR(pipe_mnt)) {
			err = PTR_ERR(pipe_mnt);
			unregister_filesystem(&pipe_fs_type);
		}
	}
#ifdef CONFIG_SYSCTL
	register_sysctl_init("fs", fs_pipe_sysctls);
#endif
	return err;
}

fs_initcall(init_pipe_fs);
