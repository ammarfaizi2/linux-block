#ifndef _ASM_X86_ATOMIC_H
#define _ASM_X86_ATOMIC_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/alternative.h>
#include <asm/cmpxchg.h>
#include <asm/rmwcc.h>
#include <asm/barrier.h>

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 */

#include <asm-generic/iso-atomic.h>

#ifdef CONFIG_X86_32
# include <asm/atomic64_32.h>
#else
# include <asm-generic/iso-atomic64.h>
#endif

#include <asm-generic/iso-atomic-long.h>

#endif /* _ASM_X86_ATOMIC_H */
