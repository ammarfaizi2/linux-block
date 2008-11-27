#ifndef _ASM_GENERIC_SYSLET_H
#define _ASM_GENERIC_SYSLET_H

/*
 * This provider of the arch-specific syslet APIs is used when an architecture
 * doesn't support syslets.
 */

/* this stops the other functions from ever being called */
static inline int syslet_frame_valid(struct syslet_frame *frame)
{
	return 0;
}

static inline void set_user_frame(struct task_struct *task,
				  struct syslet_frame *frame)
{
	BUG();
}

static inline void move_user_context(struct task_struct *dest,
					struct task_struct *src)
{
	BUG();
}

static inline int create_syslet_thread(long (*fn)(void *),
				       void *arg, unsigned long flags)
{
	BUG();
	return 0;
}

#endif
