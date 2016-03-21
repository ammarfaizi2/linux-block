#ifndef _ASM_FSGS_H
#define _ASM_FSGS_H 1

#ifndef __ASSEMBLY__

#ifdef CONFIG_X86_64

#include <asm/msr-index.h>

/* Read FSBASE for the current task. */
static inline unsigned long read_fs_base(void)
{
	unsigned long base;

	rdmsrl(MSR_FS_BASE, base);
	return base;
}

/* Read GSBASE for the current task. */
static inline unsigned long read_inactive_gs_base(void)
{
	unsigned long base;

	rdmsrl(MSR_KERNEL_GS_BASE, base);
	return base;
}

/*
 * Read an inactive task's fsbase or gsbase.  This returns the value
 * that the segment base would have if the task were to be resumed.
 */
extern unsigned long read_task_fsbase(struct task_struct *task);
extern unsigned long read_task_gsbase(struct task_struct *task);

static __always_inline void swapgs(void)
{
	asm volatile("swapgs" ::: "memory");
}

/* Must be protected by X86_FEATURE_FSGSBASE check. */

static __always_inline unsigned long rdgsbase(void)
{
	unsigned long gsbase;
	asm volatile(".byte 0xf3,0x48,0x0f,0xae,0xc8 # rdgsbaseq %%rax"
			: "=a" (gsbase)
			:: "memory");
	return gsbase;
}

static __always_inline unsigned long rdfsbase(void)
{
	unsigned long fsbase;
	asm volatile(".byte 0xf3,0x48,0x0f,0xae,0xc0 # rdfsbaseq %%rax"
			: "=a" (fsbase)
			:: "memory");
	return fsbase;
}

static __always_inline void wrgsbase(unsigned long gsbase)
{
	asm volatile(".byte 0xf3,0x48,0x0f,0xae,0xd8 # wrgsbaseq %%rax"
			:: "a" (gsbase)
			: "memory");
}

static __always_inline void wrfsbase(unsigned long fsbase)
{
	asm volatile(".byte 0xf3,0x48,0x0f,0xae,0xd0 # wrfsbaseq %%rax"
			:: "a" (fsbase)
			: "memory");
}

#endif /* CONFIG_X86_64 */

#else /* __ASSEMBLY__ */

#ifdef CONFIG_X86_64

/* Handle old assemblers. */
#define RDGSBASE_R15 .byte 0xf3,0x49,0x0f,0xae,0xcf
#define WRGSBASE_RDI .byte 0xf3,0x48,0x0f,0xae,0xdf
#define WRGSBASE_R15 .byte 0xf3,0x49,0x0f,0xae,0xdf

#endif /* CONFIG_X86_64 */

#endif /* __ASSEMBLY__ */

#endif
