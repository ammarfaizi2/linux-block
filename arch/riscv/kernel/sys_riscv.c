// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2014 Darius Rad <darius@bluespec.com>
 * Copyright (C) 2017 SiFive
 */

#include <linux/syscalls.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/hwprobe.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm-generic/mman-common.h>

static long riscv_sys_mmap(unsigned long addr, unsigned long len,
			   unsigned long prot, unsigned long flags,
			   unsigned long fd, off_t offset,
			   unsigned long page_shift_offset)
{
	if (unlikely(offset & (~PAGE_MASK >> page_shift_offset)))
		return -EINVAL;

	if (unlikely((prot & PROT_WRITE) && !(prot & PROT_READ)))
		return -EINVAL;

	return ksys_mmap_pgoff(addr, len, prot, flags, fd,
			       offset >> (PAGE_SHIFT - page_shift_offset));
}

#ifdef CONFIG_64BIT
SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, off_t, offset)
{
	return riscv_sys_mmap(addr, len, prot, flags, fd, offset, 0);
}
#endif

#if defined(CONFIG_32BIT) || defined(CONFIG_COMPAT)
SYSCALL_DEFINE6(mmap2, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, off_t, offset)
{
	/*
	 * Note that the shift for mmap2 is constant (12),
	 * regardless of PAGE_SIZE
	 */
	return riscv_sys_mmap(addr, len, prot, flags, fd, offset, 12);
}
#endif

/*
 * Allows the instruction cache to be flushed from userspace.  Despite RISC-V
 * having a direct 'fence.i' instruction available to userspace (which we
 * can't trap!), that's not actually viable when running on Linux because the
 * kernel might schedule a process on another hart.  There is no way for
 * userspace to handle this without invoking the kernel (as it doesn't know the
 * thread->hart mappings), so we've defined a RISC-V specific system call to
 * flush the instruction cache.
 *
 * sys_riscv_flush_icache() is defined to flush the instruction cache over an
 * address range, with the flush applying to either all threads or just the
 * caller.  We don't currently do anything with the address range, that's just
 * in there for forwards compatibility.
 */
SYSCALL_DEFINE3(riscv_flush_icache, uintptr_t, start, uintptr_t, end,
	uintptr_t, flags)
{
	/* Check the reserved flags. */
	if (unlikely(flags & ~SYS_RISCV_FLUSH_ICACHE_ALL))
		return -EINVAL;

	flush_icache_mm(current->mm, flags & SYS_RISCV_FLUSH_ICACHE_LOCAL);

	return 0;
}

static long set_hwprobe(struct riscv_hwprobe __user *pair, u64 key, u64 val)
{
	long ret;

	ret = put_user(key, &pair->key);
	if (ret < 0)
		return ret;
	ret = put_user(val, &pair->val);
	if (ret < 0)
		return ret;

	return 0;
}

static long hwprobe_mid(struct riscv_hwprobe __user *pair, size_t key,
			cpumask_t *cpus)
{
	long cpu, id;
	bool first, valid;

	first = true;
	valid = false;
	for_each_cpu(cpu, cpus) {
		struct riscv_cpuinfo * ci = per_cpu_ptr(&riscv_cpuinfo, cpu);
		long cpu_id;

		switch (key) {
		case RISCV_HWPROBE_KEY_MVENDORID:
			cpu_id = ci->mvendorid;
			break;
		case RISCV_HWPROBE_KEY_MIMPID:
			cpu_id = ci->mimpid;
			break;
		case RISCV_HWPROBE_KEY_MARCHID:
			cpu_id = ci->marchid;
			break;
		}

		if (first) {
			id = cpu_id;
			valid = true;
		}

		if (id != cpu_id)
			valid = false;
	}

	/*
	 * put_user() returns 0 on success, so use 1 to indicate it wasn't
	 * called and we should skip having incremented the output.
	 */
	if (!valid)
		return 1;

	return set_hwprobe(pair, key, id);
}

static
long do_riscv_hwprobe(struct riscv_hwprobe __user *pairs, long pair_count,
		      long key_offset, long cpu_count,
		      unsigned long __user *cpus_user, unsigned long flags)
{
	size_t out, k;
	long ret;
	struct cpumask cpus;

	/* Check the reserved flags. */
	if (flags != 0)
		return -EINVAL;

	/*
	 * The only supported values must be the same on all CPUs, but check to
	 * make sure userspace at least tried to provide something here for
	 * future compatibility.
	 */
	cpumask_clear(&cpus);
	if (cpu_count > cpumask_size())
		cpu_count = cpumask_size();
	ret = copy_from_user(&cpus, cpus_user, cpu_count);
	if (!ret)
		return -EFAULT;

	out = 0;
	k = key_offset;
	while (out < pair_count && k < RISCV_HWPROBE_MAX_KEY) {
		long ret;

		switch (k) {
		case RISCV_HWPROBE_KEY_MVENDORID:
		case RISCV_HWPROBE_KEY_MARCHID:
		case RISCV_HWPROBE_KEY_MIMPID:
			ret = hwprobe_mid(pairs + out, k, &cpus);
			break;
		}

		if (ret < 0)
			return ret;
		if (ret == 0)
			out++;
	}

	return out;

}

SYSCALL_DEFINE6(riscv_hwprobe, uintptr_t, pairs, uintptr_t, pair_count,
		uintptr_t, offset, uintptr_t, cpu_count, uintptr_t, cpus,
		uintptr_t, flags)
{
	return do_riscv_hwprobe((void __user *)pairs, pair_count, offset,
				cpu_count, (void __user *)cpus, flags);
}
