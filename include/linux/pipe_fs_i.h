/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PIPE_FS_I_H
#define _LINUX_PIPE_FS_I_H

#define PIPE_DEF_BUFFERS	16

#define PIPE_BUF_FLAG_LRU	0x01	/* page is on the LRU */
#define PIPE_BUF_FLAG_ATOMIC	0x02	/* was atomically mapped */
#define PIPE_BUF_FLAG_GIFT	0x04	/* page is a gift */
#define PIPE_BUF_FLAG_PACKET	0x08	/* read() as a packet */
#define PIPE_BUF_FLAG_CAN_MERGE	0x10	/* can merge buffers */
#define PIPE_BUF_FLAG_WHOLE	0x20	/* read() must return entire buffer or error */
#ifdef CONFIG_WATCH_QUEUE
#define PIPE_BUF_FLAG_LOSS	0x40	/* Message loss happened after this buffer */
#endif

/**
 *	struct pipe_buffer - a linux kernel pipe buffer
 *	@page: the page containing the data for the pipe buffer
 *	@offset: offset of data inside the @page
 *	@len: length of data inside the @page
 *	@ops: operations associated with this buffer. See @pipe_buf_operations.
 *	@flags: pipe buffer flags. See above.
 *	@private: private data owned by the ops.
 **/
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

/*
 * Note on the nesting of these functions:
 *
 * ->confirm()
 *	->try_steal()
 *
 * That is, ->try_steal() must be called on a confirmed buffer.  See below for
 * the meaning of each operation.  Also see the kerneldoc in fs/pipe.c for the
 * pipe and generic variants of these hooks.
 */
struct pipe_buf_operations {
	/*
	 * ->confirm() verifies that the data in the pipe buffer is there
	 * and that the contents are good. If the pages in the pipe belong
	 * to a file system, we may need to wait for IO completion in this
	 * hook. Returns 0 for good, or a negative error value in case of
	 * error.  If not present all pages are considered good.
	 */
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * When the contents of this pipe buffer has been completely
	 * consumed by a reader, ->release() is called.
	 */
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Attempt to take ownership of the pipe buffer and its contents.
	 * ->try_steal() returns %true for success, in which case the contents
	 * of the pipe (the buf->page) is locked and now completely owned by the
	 * caller. The page may then be transferred to a different mapping, the
	 * most often used case is insertion into different file address space
	 * cache.
	 */
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Get a reference to the pipe buffer.
	 */
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

/**
 * pipe_buf_get - get a reference to a pipe_buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to get a reference to
 *
 * Return: %true if the reference was successfully obtained.
 */
static inline __must_check bool pipe_buf_get(struct pipe_inode_info *pipe,
				struct pipe_buffer *buf)
{
	return buf->ops->get(pipe, buf);
}

/**
 * pipe_buf_release - put a reference to a pipe_buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to put a reference to
 */
static inline void pipe_buf_release(struct pipe_inode_info *pipe,
				    struct pipe_buffer *buf)
{
	const struct pipe_buf_operations *ops = buf->ops;

	buf->ops = NULL;
	ops->release(pipe, buf);
}

/**
 * pipe_buf_confirm - verify contents of the pipe buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to confirm
 */
static inline int pipe_buf_confirm(struct pipe_inode_info *pipe,
				   struct pipe_buffer *buf)
{
	if (!buf->ops->confirm)
		return 0;
	return buf->ops->confirm(pipe, buf);
}

/**
 * pipe_buf_try_steal - attempt to take ownership of a pipe_buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to attempt to steal
 */
static inline bool pipe_buf_try_steal(struct pipe_inode_info *pipe,
		struct pipe_buffer *buf)
{
	if (!buf->ops->try_steal)
		return false;
	return buf->ops->try_steal(pipe, buf);
}

/* Add data to a pipe */
size_t pipe_query_space(struct pipe_inode_info *pipe, size_t *len, int *error);
struct pipe_buffer *pipe_alloc_buffer(struct pipe_inode_info *pipe,
				      const struct pipe_buf_operations *ops,
				      size_t bvcount, gfp_t gfp, int *error);
ssize_t pipe_add(struct pipe_inode_info *pipe, struct pipe_buffer *buf, bool *full);
#ifdef CONFIG_WATCH_QUEUE
void pipe_set_lost_mark(struct pipe_inode_info *pipe);
#endif

/* Get data from a pipe */
size_t pipe_query_content(struct pipe_inode_info *pipe, size_t *len);

/* Pipe lock and unlock operations */
void pipe_lock(struct pipe_inode_info *);
void pipe_unlock(struct pipe_inode_info *);
void pipe_double_lock(struct pipe_inode_info *, struct pipe_inode_info *);

/* Generic pipe buffer ops functions */
bool generic_pipe_buf_get(struct pipe_inode_info *, struct pipe_buffer *);
bool generic_pipe_buf_try_steal(struct pipe_inode_info *, struct pipe_buffer *);
void generic_pipe_buf_release(struct pipe_inode_info *, struct pipe_buffer *);

extern const struct pipe_buf_operations nosteal_pipe_buf_ops;

int create_pipe_files(struct file **, int);
void free_pipe_info(struct pipe_inode_info *);

#endif
