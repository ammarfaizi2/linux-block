// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/regset.h>

#include <asm/switch_to.h>

#include "ptrace-decl.h"

/*
 * For get_evrregs/set_evrregs functions 'data' has the following layout:
 *
 * struct {
 *   u32 evr[32];
 *   u64 acc;
 *   u32 spefscr;
 * }
 */

int evr_active(struct task_struct *target, const struct user_regset *regset)
{
	flush_spe_to_thread(target);
	return task_thread(target).used_spe ? regset->n : 0;
}

int evr_get(struct task_struct *target, const struct user_regset *regset,
	    struct membuf to)
{
	flush_spe_to_thread(target);

	membuf_write(&to, &task_thread(target).evr, sizeof(task_thread(target).evr));

	BUILD_BUG_ON(offsetof(struct thread_struct, acc) + sizeof(u64) !=
		     offsetof(struct thread_struct, spefscr));

	return membuf_write(&to, &task_thread(target).acc,
				sizeof(u64) + sizeof(u32));
}

int evr_set(struct task_struct *target, const struct user_regset *regset,
	    unsigned int pos, unsigned int count,
	    const void *kbuf, const void __user *ubuf)
{
	int ret;

	flush_spe_to_thread(target);

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 &task_thread(target).evr,
				 0, sizeof(task_thread(target).evr));

	BUILD_BUG_ON(offsetof(struct thread_struct, acc) + sizeof(u64) !=
		     offsetof(struct thread_struct, spefscr));

	if (!ret)
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
					 &task_thread(target).acc,
					 sizeof(task_thread(target).evr), -1);

	return ret;
}
