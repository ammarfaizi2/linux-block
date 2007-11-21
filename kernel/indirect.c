#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <asm/asm-offsets.h>


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

	switch (INDIRECT_SYSCALL (&regs))
	{
#define INDSYSCALL(name) __NR_##name
#include <linux/indirect.h>
		break;

	default:
		return -EINVAL;
	}

	if (paramslen > sizeof(union indirect_params))
		return -EINVAL;

	result = -EFAULT;
	if (!copy_from_user(&current->indirect_params, userparams, paramslen))
		result = call_indirect(&regs);

	memset(&current->indirect_params, '\0', paramslen);

	return result;
}
