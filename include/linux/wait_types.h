/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_WAIT_TYPES_H
#define _LINUX_WAIT_TYPES_H

/*
 * Linux wait queue related types and methods
 */
#include <linux/spinlock_types.h>

#include <uapi/linux/wait.h>

typedef struct wait_queue_entry wait_queue_entry_t;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key);
int default_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int flags, void *key);

/* wait_queue_entry::flags */
#define WQ_FLAG_EXCLUSIVE	0x01
#define WQ_FLAG_WOKEN		0x02
#define WQ_FLAG_BOOKMARK	0x04
#define WQ_FLAG_CUSTOM		0x08
#define WQ_FLAG_DONE		0x10
#define WQ_FLAG_PRIORITY	0x20

/*
 * A single wait-queue entry structure:
 */
struct wait_queue_entry {
	unsigned int		flags;
	void			*private;
	wait_queue_func_t	func;
	struct list_head	entry;
};

struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};
typedef struct wait_queue_head wait_queue_head_t;

struct task_struct;

/*
 * Macros for declaration and initialisaton of the datatypes
 */

#define __WAITQUEUE_INITIALIZER(name, tsk) {					\
	.private	= tsk,							\
	.func		= default_wake_function,				\
	.entry		= { NULL, NULL } }

#define DECLARE_WAITQUEUE(name, tsk)						\
	struct wait_queue_entry name = __WAITQUEUE_INITIALIZER(name, tsk)

#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {					\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),			\
	.head		= LIST_HEAD_INIT(name.head) }

#define DECLARE_WAIT_QUEUE_HEAD(name) \
	struct wait_queue_head name = __WAIT_QUEUE_HEAD_INITIALIZER(name)

extern void __init_waitqueue_head(struct wait_queue_head *wq_head, const char *name, struct lock_class_key *);

#define init_waitqueue_head(wq_head)						\
	do {									\
		static struct lock_class_key __key;				\
										\
		__init_waitqueue_head((wq_head), #wq_head, &__key);		\
	} while (0)

#ifdef CONFIG_LOCKDEP
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) \
	struct wait_queue_head name = __WAIT_QUEUE_HEAD_INIT_ONSTACK(name)
#else
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) DECLARE_WAIT_QUEUE_HEAD(name)
#endif

static inline void init_waitqueue_entry(struct wait_queue_entry *wq_entry, struct task_struct *p)
{
	wq_entry->flags		= 0;
	wq_entry->private	= p;
	wq_entry->func		= default_wake_function;
}

static inline void
init_waitqueue_func_entry(struct wait_queue_entry *wq_entry, wait_queue_func_t func)
{
	wq_entry->flags		= 0;
	wq_entry->private	= NULL;
	wq_entry->func		= func;
}

extern void init_wait_entry(struct wait_queue_entry *wq_entry, int flags);

#define DEFINE_WAIT_FUNC(name, function)					\
	struct wait_queue_entry name = {					\
		.private	= current,					\
		.func		= function,					\
		.entry		= LIST_HEAD_INIT((name).entry),			\
	}

#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)

#define init_wait(wait)								\
	do {									\
		(wait)->private = current;					\
		(wait)->func = autoremove_wake_function;			\
		INIT_LIST_HEAD(&(wait)->entry);					\
		(wait)->flags = 0;						\
	} while (0)

#endif /* _LINUX_WAIT_TYPES_H */
