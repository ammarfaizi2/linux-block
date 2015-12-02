#ifndef _LINUX_POLL_H
#define _LINUX_POLL_H

#include <linux/compiler.h>
#include <linux/wait.h>
#include <asm/uaccess.h>
#include <uapi/linux/poll.h>

#define DEFAULT_POLLMASK (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)

struct poll_table_struct;
struct file;

/* 
 * structures and helpers for f_op->poll implementations
 */
typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

/*
 * Do not touch the structure directly, use the access functions
 * poll_does_not_wait() and poll_requested_events() instead.
 */
typedef struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
} poll_table;

static inline void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p)
{
	if (p && p->_qproc && wait_address)
		p->_qproc(filp, wait_address, p);
}

/*
 * Return true if it is guaranteed that poll will not wait. This is the case
 * if the poll() of another file descriptor in the set got an event, so there
 * is no need for waiting.
 */
static inline bool poll_does_not_wait(const poll_table *p)
{
	return p == NULL || p->_qproc == NULL;
}

/*
 * Return the set of events that the application wants to poll for.
 * This is useful for drivers that need to know whether a DMA transfer has
 * to be started implicitly on poll(). You typically only want to do that
 * if the application is actually polling for POLLIN and/or POLLOUT.
 */
static inline __poll_t poll_requested_events(const poll_table *p)
{
	return p ? p->_key : (__force __poll_t)~0UL;
}

static inline void init_poll_funcptr(poll_table *pt, poll_queue_proc qproc)
{
	pt->_qproc = qproc;
	pt->_key   = (__force __poll_t)~0UL; /* all events enabled */
}
#endif /* _LINUX_POLL_H */
