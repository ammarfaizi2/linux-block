/* thread_info.h: common low-level thread information accessors
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * - Incorporating suggestions made by Linus Torvalds
 */

#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/restart_block.h>
#include <linux/thread_bits.h>

#include <linux/bitops.h>
#include <asm/thread_info.h>

#ifdef __KERNEL__

#ifdef CONFIG_DEBUG_STACK_USAGE
# define THREADINFO_GFP		(GFP_KERNEL_ACCOUNT | __GFP_NOTRACK | \
				 __GFP_ZERO)
#else
# define THREADINFO_GFP		(GFP_KERNEL_ACCOUNT | __GFP_NOTRACK)
#endif

#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)

#ifndef CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES
static inline int arch_within_stack_frames(const void * const stack,
					   const void * const stackend,
					   const void *obj, unsigned long len)
{
	return 0;
}
#endif

#ifdef CONFIG_HARDENED_USERCOPY
extern void __check_object_size(const void *ptr, unsigned long n,
					bool to_user);

static __always_inline void check_object_size(const void *ptr, unsigned long n,
					      bool to_user)
{
	if (!__builtin_constant_p(n))
		__check_object_size(ptr, n, to_user);
}
#else
static inline void check_object_size(const void *ptr, unsigned long n,
				     bool to_user)
{ }
#endif /* CONFIG_HARDENED_USERCOPY */

#ifndef arch_setup_new_exec
static inline void arch_setup_new_exec(void) { }
#endif

#endif	/* __KERNEL__ */

#endif /* _LINUX_THREAD_INFO_H */
