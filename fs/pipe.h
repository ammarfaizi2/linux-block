/* SPDX-License-Identifier: GPL-2.0 */

/**
 *	struct pipe_inode_info - a linux kernel pipe
 *	@mutex: mutex protecting the whole thing
 *	@queue: The pipe buffer.
 *	@rd_wait: reader wait point in case of empty pipe
 *	@wr_wait: writer wait point in case of full pipe
 *	@note_loss: The next read() should insert a data-lost message
 *	@footprint: The amount of space pinned by the pipe (in pages).
 *	@max_footprint: The maximum amount of space that can be pinned (in pages).
 *	@content: The amount of content (in bytes).
 *	@spare_folio: Cached released folio
 *	@spare_buffer: Cached released buffer
 *	@readers: number of current readers of this pipe
 *	@writers: number of current writers of this pipe
 *	@files: number of struct file referring this pipe (protected by ->i_lock)
 *	@r_counter: reader counter
 *	@w_counter: writer counter
 *	@poll_usage: is this pipe used for epoll, which has crazy wakeups?
 *	@fasync_readers: reader side fasync
 *	@fasync_writers: writer side fasync
 *	@user: the user who created this pipe
 *	@watch_queue: If this pipe is a watch_queue, this is the stuff for that
 **/
struct pipe_inode_info {
	struct mutex		mutex;
	struct list_head	queue;
	wait_queue_head_t	rd_wait, wr_wait;
#ifdef CONFIG_WATCH_QUEUE
	bool			note_loss;
#endif
	size_t			footprint;
	size_t			max_footprint;
	size_t			content;
	unsigned int		readers;
	unsigned int		writers;
	unsigned int		files;
	unsigned int		r_counter;
	unsigned int		w_counter;
	bool			poll_usage;
	struct folio		*spare_folio;
	struct pipe_buffer	*spare_buffer;
	struct fasync_struct	*fasync_readers;
	struct fasync_struct	*fasync_writers;
	struct user_struct	*user;
#ifdef CONFIG_WATCH_QUEUE
	struct watch_queue	*watch_queue;
#endif
};

/**
 * pipe_empty - Return true if the pipe is empty
 * @pipe: The pipe to query
 */
static inline bool pipe_empty(const struct pipe_inode_info *pipe)
{
	return list_empty(&pipe->queue);
}

/**
 * pipe_full - Return true if the pipe is full
 * @pipe: The pipe to query
 */
static inline bool pipe_full(const struct pipe_inode_info *pipe)
{
	return pipe->footprint >= pipe->max_footprint;
}

/**
 * pipe_occupancy - Return number of pages remaining in a pipe
 * @pipe: The pipe to query
 */
static inline size_t pipe_occupancy(const struct pipe_inode_info *pipe)
{
	return min_t(ssize_t, pipe->max_footprint - pipe->footprint, 0);
}

/**
 * pipe_head_buf - Return the head pipe buffer or NULL
 * @pipe: The pipe to access
 */
static inline struct pipe_buffer *pipe_head_buf(struct pipe_inode_info *pipe)
{
	return list_first_entry_or_null(&pipe->queue,
					struct pipe_buffer, queue_link);
}

/* Wait for a pipe to be readable/writable while dropping the pipe lock */
void pipe_wait_readable(struct pipe_inode_info *);
void pipe_wait_writable(struct pipe_inode_info *);

struct pipe_inode_info *alloc_pipe_info(void);
bool pipe_consume(struct pipe_inode_info *pipe, struct pipe_buffer *buf, size_t consumed);
