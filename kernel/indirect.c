#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <asm/asm-offsets.h>

/* XXX would we prefer to generalize this somehow? */
#include <linux/syslet.h>

asmlinkage long sys_indirect(struct indirect_registers __user *userregs,
			     void __user *userparams, size_t paramslen,
			     int flags)
{
	struct indirect_registers regs;
	long result;

	if (unlikely(flags != 0))
		return -EINVAL;

	if (copy_from_user(&regs, userregs, sizeof(regs)))
		return -EFAULT;

	if (paramslen > sizeof(union indirect_params))
		return -EINVAL;

	if (copy_from_user(&current->indirect_params, userparams, paramslen)) {
		result = -EFAULT;
		goto out;
	}

	/* We need to come up with a better way to allow and forbid syscalls */
	if (unlikely(syslet_args_present(&current->indirect_params))) {
		result = syslet_pre_indirect();
		if (result == 0) {
			result = call_indirect(&regs);
			result = syslet_post_indirect(result);
		}
		goto out;
	}

	switch (INDIRECT_SYSCALL (&regs))
	{
#define INDSYSCALL(name) __NR_##name
#include <linux/indirect.h>
		break;

	default:
		result = -EINVAL;
		goto out;
	}

	result = call_indirect(&regs);
out:
	memset(&current->indirect_params, '\0', paramslen);

	return result;
}
