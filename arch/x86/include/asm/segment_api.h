/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SEGMENT_API_H
#define _ASM_X86_SEGMENT_API_H

#include <asm/segment_types.h>

#include <linux/const.h>
#include <asm/alternative.h>

#ifdef CONFIG_X86_32

#else /* 64-bit: */

#include <asm/cache.h>

#endif

#ifdef CONFIG_X86_64
#ifndef __ASSEMBLY__

/* Helper functions to store/load CPU and node numbers */

static inline unsigned long vdso_encode_cpunode(int cpu, unsigned long node)
{
	return (node << VDSO_CPUNODE_BITS) | cpu;
}

static inline void vdso_read_cpunode(unsigned *cpu, unsigned *node)
{
	unsigned int p;

	/*
	 * Load CPU and node number from the GDT.  LSL is faster than RDTSCP
	 * and works on all CPUs.  This is volatile so that it orders
	 * correctly with respect to barrier() and to keep GCC from cleverly
	 * hoisting it out of the calling function.
	 *
	 * If RDPID is available, use it.
	 */
	alternative_io ("lsl %[seg],%[p]",
			".byte 0xf3,0x0f,0xc7,0xf8", /* RDPID %eax/rax */
			X86_FEATURE_RDPID,
			[p] "=a" (p), [seg] "r" (__CPUNODE_SEG));

	if (cpu)
		*cpu = (p & VDSO_CPUNODE_MASK);
	if (node)
		*node = (p >> VDSO_CPUNODE_BITS);
}

#endif /* !__ASSEMBLY__ */
#endif /* CONFIG_X86_64 */

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

extern const char early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE];
extern void early_ignore_irq(void);

#ifdef CONFIG_XEN_PV
extern const char xen_early_idt_handler_array[NUM_EXCEPTION_VECTORS][XEN_EARLY_IDT_HANDLER_SIZE];
#endif

/*
 * Load a segment. Fall back on loading the zero segment if something goes
 * wrong.  This variant assumes that loading zero fully clears the segment.
 * This is always the case on Intel CPUs and, even on 64-bit AMD CPUs, any
 * failure to fully clear the cached descriptor is only observable for
 * FS and GS.
 */
#define __loadsegment_simple(seg, value)				\
do {									\
	unsigned short __val = (value);					\
									\
	asm volatile("						\n"	\
		     "1:	movl %k0,%%" #seg "		\n"	\
		     _ASM_EXTABLE_TYPE_REG(1b, 1b, EX_TYPE_ZERO_REG, %k0)\
		     : "+r" (__val) : : "memory");			\
} while (0)

#define __loadsegment_ss(value) __loadsegment_simple(ss, (value))
#define __loadsegment_ds(value) __loadsegment_simple(ds, (value))
#define __loadsegment_es(value) __loadsegment_simple(es, (value))

#ifdef CONFIG_X86_32

/*
 * On 32-bit systems, the hidden parts of FS and GS are unobservable if
 * the selector is NULL, so there's no funny business here.
 */
#define __loadsegment_fs(value) __loadsegment_simple(fs, (value))
#define __loadsegment_gs(value) __loadsegment_simple(gs, (value))

#else

static inline void __loadsegment_fs(unsigned short value)
{
	asm volatile("						\n"
		     "1:	movw %0, %%fs			\n"
		     "2:					\n"

		     _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_CLEAR_FS)

		     : : "rm" (value) : "memory");
}

/* __loadsegment_gs is intentionally undefined.  Use load_gs_index instead. */

#endif

#define loadsegment(seg, value) __loadsegment_ ## seg (value)

/*
 * Save a segment register away:
 */
#define savesegment(seg, value)				\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")

/*
 * x86-32 user GS accessors.  This is ugly and could do with some cleaning up.
 */
#ifdef CONFIG_X86_32
# define get_user_gs(regs)		(u16)({ unsigned long v; savesegment(gs, v); v; })
# define set_user_gs(regs, v)		loadsegment(gs, (unsigned long)(v))
# define task_user_gs(tsk)		(task_thread(tsk).gs)
# define lazy_save_gs(v)		savesegment(gs, (v))
# define lazy_load_gs(v)		loadsegment(gs, (v))
# define load_gs_index(v)		loadsegment(gs, (v))
#endif	/* X86_32 */

#endif /* !__ASSEMBLY__ */
#endif /* __KERNEL__ */

#endif /* _ASM_X86_SEGMENT_API_H */
