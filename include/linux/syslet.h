#ifndef _LINUX_SYSLET_H
#define _LINUX_SYSLET_H

#include <linux/syslet-abi.h>
#include <asm/syslet.h>

void syslet_init(struct task_struct *tsk);
void kill_syslet_tasks(struct task_struct *cur);
void syslet_schedule(struct task_struct *cur);
int syslet_pre_indirect(void);
int syslet_post_indirect(int status);

static inline int syslet_args_present(union indirect_params *params)
{
	return params->syslet.completion_ring_ptr;
}

#endif
