#ifndef __ASM_X86_SYSLET_H
#define __ASM_X86_SYSLET_H

#include "syslet-abi.h"

/* These are provided by kernel/entry.S and kernel/process.c */
void move_user_context(struct task_struct *dest, struct task_struct *src);
int create_syslet_thread(long (*fn)(void *),
			 void *arg, unsigned long flags);

static inline int syslet_frame_valid(struct syslet_frame *frame)
{
	return frame->ip && frame->sp;
}

#ifdef CONFIG_X86_32
static inline void set_user_frame(struct task_struct *task,
				  struct syslet_frame *frame)
{
	task_pt_regs(task)->eip = frame->ip;
	task_pt_regs(task)->esp = frame->sp;
}
#else
static inline void set_user_frame(struct task_struct *task,
				  struct syslet_frame *frame)
{
	task_pt_regs(task)->rip = frame->ip;
	task_pt_regs(task)->rsp = frame->sp;
}
#endif

#endif
