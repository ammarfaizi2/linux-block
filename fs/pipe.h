/* SPDX-License-Identifier: GPL-2.0 */

/**
 *	struct pipe_inode_info - a linux kernel pipe
 *	@mutex: mutex protecting the whole thing
 *	@rd_wait: reader wait point in case of empty pipe
 *	@wr_wait: writer wait point in case of full pipe
 *	@head: The point of buffer production
 *	@tail: The point of buffer consumption
 *	@note_loss: The next read() should insert a data-lost message
 *	@max_usage: The maximum number of slots that may be used in the ring
 *	@ring_size: total number of buffers (should be a power of 2)
 *	@nr_accounted: The amount this pipe accounts for in user->pipe_bufs
 *	@tmp_page: cached released page
 *	@readers: number of current readers of this pipe
 *	@writers: number of current writers of this pipe
 *	@files: number of struct file referring this pipe (protected by ->i_lock)
 *	@r_counter: reader counter
 *	@w_counter: writer counter
 *	@poll_usage: is this pipe used for epoll, which has crazy wakeups?
 *	@fasync_readers: reader side fasync
 *	@fasync_writers: writer side fasync
 *	@bufs: the circular array of pipe buffers
 *	@user: the user who created this pipe
 *	@watch_queue: If this pipe is a watch_queue, this is the stuff for that
 **/
struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait, wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
#ifdef CONFIG_WATCH_QUEUE
	bool note_loss;
#endif
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
#ifdef CONFIG_WATCH_QUEUE
	struct watch_queue *watch_queue;
#endif
};

/**
 * pipe_empty - Return true if the pipe is empty
 * @head: The pipe ring head pointer
 * @tail: The pipe ring tail pointer
 */
static inline bool pipe_empty(unsigned int head, unsigned int tail)
{
	return head == tail;
}

/**
 * pipe_occupancy - Return number of slots used in the pipe
 * @head: The pipe ring head pointer
 * @tail: The pipe ring tail pointer
 */
static inline unsigned int pipe_occupancy(unsigned int head, unsigned int tail)
{
	return head - tail;
}

/**
 * pipe_full - Return true if the pipe is full
 * @head: The pipe ring head pointer
 * @tail: The pipe ring tail pointer
 * @limit: The maximum amount of slots available.
 */
static inline bool pipe_full(unsigned int head, unsigned int tail,
			     unsigned int limit)
{
	return pipe_occupancy(head, tail) >= limit;
}

/**
 * pipe_buf - Return the pipe buffer for the specified slot in the pipe ring
 * @pipe: The pipe to access
 * @slot: The slot of interest
 */
static inline struct pipe_buffer *pipe_buf(const struct pipe_inode_info *pipe,
					   unsigned int slot)
{
	return &pipe->bufs[slot & (pipe->ring_size - 1)];
}

/**
 * pipe_head_buf - Return the pipe buffer at the head of the pipe ring
 * @pipe: The pipe to access
 */
static inline struct pipe_buffer *pipe_head_buf(const struct pipe_inode_info *pipe)
{
	return pipe_buf(pipe, pipe->head);
}

/* Wait for a pipe to be readable/writable while dropping the pipe lock */
void pipe_wait_readable(struct pipe_inode_info *);
void pipe_wait_writable(struct pipe_inode_info *);

struct pipe_inode_info *alloc_pipe_info(void);

#ifdef CONFIG_WATCH_QUEUE
unsigned long account_pipe_buffers(struct user_struct *user,
				   unsigned long old, unsigned long new);
bool too_many_pipe_buffers_soft(unsigned long user_bufs);
bool too_many_pipe_buffers_hard(unsigned long user_bufs);
bool pipe_is_unprivileged_user(void);
#endif

/* for F_SETPIPE_SZ and F_GETPIPE_SZ */
#ifdef CONFIG_WATCH_QUEUE
int pipe_resize_ring(struct pipe_inode_info *pipe, unsigned int nr_slots);
#endif
