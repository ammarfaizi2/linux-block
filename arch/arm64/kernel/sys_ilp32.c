/*
 * AArch64- ILP32 specific system calls implementation
 *
 * Copyright (C) 2017 Cavium Inc.
 * Author: Andrew Pinski <apinski@cavium.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define __SYSCALL_COMPAT

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/msg.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <asm-generic/syscalls.h>

/*
 * AARCH32 requires 4-page alignement for shared memory,
 * but AARCH64 - only 1 page. This is the only difference
 * between compat and native sys_shmat(). So ILP32 just pick
 * AARCH64 version.
 */
#define compat_sys_shmat		sys_shmat

/*
 * ILP32 needs special handling for some ptrace requests.
 */
#define sys_ptrace			compat_sys_ptrace

/*
 * Using AARCH32 interface for syscalls that take 64-bit
 * parameters in registers.
 */
#define compat_sys_fadvise64_64		compat_sys_fadvise64_64_wrapper
#define compat_sys_fallocate		compat_sys_fallocate_wrapper
#define compat_sys_ftruncate64		compat_sys_ftruncate64_wrapper
#define compat_sys_pread64		compat_sys_pread64_wrapper
#define compat_sys_pwrite64		compat_sys_pwrite64_wrapper
#define compat_sys_readahead		compat_sys_readahead_wrapper
#define compat_sys_sync_file_range2	compat_sys_sync_file_range2_wrapper
#define compat_sys_truncate64		compat_sys_truncate64_wrapper
#define sys_mmap2			compat_sys_mmap2_wrapper

/*
 * Using AARCH32 interface for syscalls that take the size of
 * struct statfs as an argument, as it's calculated differently
 * in kernel and user spaces.
 */
#define compat_sys_fstatfs64		compat_sys_fstatfs64_wrapper
#define compat_sys_statfs64		compat_sys_statfs64_wrapper

/*
 * Using custom wrapper for rt_sigreturn() to handle custom
 * struct rt_sigframe.
 */
#define compat_sys_rt_sigreturn        ilp32_sys_rt_sigreturn_wrapper

asmlinkage long compat_sys_fstatfs64_wrapper(void);
asmlinkage long compat_sys_statfs64_wrapper(void);
asmlinkage long compat_sys_fadvise64_64_wrapper(void);
asmlinkage long compat_sys_fallocate_wrapper(void);
asmlinkage long compat_sys_ftruncate64_wrapper(void);
asmlinkage long compat_sys_mmap2_wrapper(void);
asmlinkage long compat_sys_pread64_wrapper(void);
asmlinkage long compat_sys_pwrite64_wrapper(void);
asmlinkage long compat_sys_readahead_wrapper(void);
asmlinkage long compat_sys_sync_file_range2_wrapper(void);
asmlinkage long compat_sys_truncate64_wrapper(void);
asmlinkage long ilp32_sys_rt_sigreturn_wrapper(void);

#include <asm/syscall.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = sym,

/*
 * The sys_call_ilp32_table array must be 4K aligned to be accessible from
 * kernel/entry.S.
 */
void *sys_call_ilp32_table[__NR_syscalls] __aligned(4096) = {
	[0 ... __NR_syscalls - 1] = sys_ni_syscall,
#include <asm/unistd.h>
};
