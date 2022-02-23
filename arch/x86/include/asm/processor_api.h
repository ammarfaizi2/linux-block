/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PROCESSOR_API_H
#define _ASM_X86_PROCESSOR_API_H

#include <asm/processor.h>
#include <asm/special_insns.h>

#include <linux/sched/thread.h>
#include <linux/thread_info.h>

/*
 * Friendlier CR3 helpers.
 */
static inline unsigned long read_cr3_pa(void)
{
	return __read_cr3() & CR3_ADDR_MASK;
}

static inline unsigned long native_read_cr3_pa(void)
{
	return __native_read_cr3() & CR3_ADDR_MASK;
}

#define load_cr3(pgdir) write_cr3(__sme_pa(pgdir))

static inline void
native_load_sp0(unsigned long sp0)
{
	this_cpu_write(cpu_tss_rw.x86_tss.sp0, sp0);
}

static __always_inline void native_swapgs(void)
{
#ifdef CONFIG_X86_64
	asm volatile("swapgs" ::: "memory");
#endif
}

static inline unsigned long current_top_of_stack(void)
{
	/*
	 *  We can't read directly from tss.sp0: sp0 on x86_32 is special in
	 *  and around vm86 mode and sp0 on x86_64 is special because of the
	 *  entry trampoline.
	 */
	return this_cpu_read_stable(cpu_current_top_of_stack);
}

static inline bool on_thread_stack(void)
{
	return (unsigned long)(current_top_of_stack() -
			       current_stack_pointer) < THREAD_SIZE;
}

#ifdef CONFIG_PARAVIRT_XXL
#include <asm/paravirt.h>
#else
#define __cpuid			native_cpuid

static inline void load_sp0(unsigned long sp0)
{
	native_load_sp0(sp0);
}

#endif /* CONFIG_PARAVIRT_XXL */


#ifdef CONFIG_X86_32
extern int have_cpuid_p(void);
#else
static inline int have_cpuid_p(void)
{
	return 1;
}
#endif
static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
	    : "=a" (*eax),
	      "=b" (*ebx),
	      "=c" (*ecx),
	      "=d" (*edx)
	    : "0" (*eax), "2" (*ecx)
	    : "memory");
}

#define native_cpuid_reg(reg)					\
static inline unsigned int native_cpuid_##reg(unsigned int op)	\
{								\
	unsigned int eax = op, ebx, ecx = 0, edx;		\
								\
	native_cpuid(&eax, &ebx, &ecx, &edx);			\
								\
	return reg;						\
}

/*
 * Native CPUID functions returning a single datum.
 */
native_cpuid_reg(eax)
native_cpuid_reg(ebx)
native_cpuid_reg(ecx)
native_cpuid_reg(edx)

/*
 * X86 doesn't need any embedded-FPU-struct quirks:
 */

static inline void arch_thread_struct_whitelist(unsigned long *offset,
						unsigned long *size)
{
	*offset = 0;
	*size = 0;
}

/* Free all resources held by a thread. */
extern void release_thread(struct task_struct *);

unsigned long __get_wchan(struct task_struct *p);

/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 */
static inline void cpuid(unsigned int op,
			 unsigned int *eax, unsigned int *ebx,
			 unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = 0;
	__cpuid(eax, ebx, ecx, edx);
}

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(unsigned int op, int count,
			       unsigned int *eax, unsigned int *ebx,
			       unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	__cpuid(eax, ebx, ecx, edx);
}

/*
 * CPUID functions returning a single datum
 */
static inline unsigned int cpuid_eax(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return eax;
}

static inline unsigned int cpuid_ebx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return ebx;
}

static inline unsigned int cpuid_ecx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return ecx;
}

static inline unsigned int cpuid_edx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return edx;
}

struct cpuinfo_x86;
extern void select_idle_routine(const struct cpuinfo_x86 *c);
extern void amd_e400_c1e_apic_setup(void);

extern unsigned long		boot_option_idle_override;

enum idle_boot_override {IDLE_NO_OVERRIDE=0, IDLE_HALT, IDLE_NOMWAIT,
			 IDLE_POLL};

extern void enable_sep_cpu(void);
extern int sysenter_setup(void);


/* Defined in head.S */
extern struct desc_ptr		early_gdt_descr;

extern void switch_to_new_gdt(int);
extern void load_direct_gdt(int);
extern void load_fixmap_gdt(int);
extern void load_percpu_segment(int);
extern void cpu_init(void);
extern void cpu_init_secondary(void);
extern void cpu_init_exception_handling(void);
extern void cr4_init(void);

extern unsigned long get_debugctlmsr(void);
extern void update_debugctlmsr(unsigned long debugctlmsr);

extern void set_task_blockstep(struct task_struct *task, bool on);

/* Boot loader type from the setup header: */
extern int			bootloader_type;
extern int			bootloader_version;

extern char			ignore_fpu_irq;

#define HAVE_ARCH_PICK_MMAP_LAYOUT 1
#define ARCH_HAS_PREFETCHW
#define ARCH_HAS_SPINLOCK_PREFETCH

#ifdef CONFIG_X86_32
# define BASE_PREFETCH		""
# define ARCH_HAS_PREFETCH
#else
# define BASE_PREFETCH		"prefetcht0 %P1"
#endif

/*
 * Prefetch instructions for Pentium III (+) and AMD Athlon (+)
 *
 * It's not worth to care about 3dnow prefetches for the K6
 * because they are microcoded there and very slow.
 */
static inline void prefetch(const void *x)
{
	alternative_input(BASE_PREFETCH, "prefetchnta %P1",
			  X86_FEATURE_XMM,
			  "m" (*(const char *)x));
}

/*
 * 3dnow prefetch to get an exclusive cache line.
 * Useful for spinlocks to avoid one state transition in the
 * cache coherency protocol:
 */
static __always_inline void prefetchw(const void *x)
{
	alternative_input(BASE_PREFETCH, "prefetchw %P1",
			  X86_FEATURE_3DNOWPREFETCH,
			  "m" (*(const char *)x));
}

static inline void spin_lock_prefetch(const void *x)
{
	prefetchw(x);
}

#define TOP_OF_INIT_STACK ((unsigned long)&init_stack + sizeof(init_stack) - \
			   TOP_OF_KERNEL_STACK_PADDING)

#define task_top_of_stack(task) ((unsigned long)(task_pt_regs(task) + 1))

#define task_pt_regs(task) \
({									\
	unsigned long __ptr = (unsigned long)task_stack_page(task);	\
	__ptr += THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;		\
	((struct pt_regs *)__ptr) - 1;					\
})

#ifdef CONFIG_X86_32
#define INIT_THREAD  {							  \
	.sp0			= TOP_OF_INIT_STACK,			  \
	.sysenter_cs		= __KERNEL_CS,				  \
}

#define KSTK_ESP(task)		(task_pt_regs(task)->sp)

#else
#define INIT_THREAD { }

extern unsigned long KSTK_ESP(struct task_struct *task);

#endif /* CONFIG_X86_64 */

extern void start_thread(struct pt_regs *regs, unsigned long new_ip,
					       unsigned long new_sp);

/*
 * This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define __TASK_UNMAPPED_BASE(task_size)	(PAGE_ALIGN(task_size / 3))
#define TASK_UNMAPPED_BASE		__TASK_UNMAPPED_BASE(TASK_SIZE_LOW)

#define KSTK_EIP(task)		(task_pt_regs(task)->ip)

/* Get/set a process' ability to use the timestamp counter instruction */
#define GET_TSC_CTL(adr)	get_tsc_mode((adr))
#define SET_TSC_CTL(val)	set_tsc_mode((val))

extern int get_tsc_mode(unsigned long adr);
extern int set_tsc_mode(unsigned int val);

DECLARE_PER_CPU(u64, msr_misc_features_shadow);

extern u16 get_llc_id(unsigned int cpu);

#ifdef CONFIG_CPU_SUP_AMD
extern u32 amd_get_nodes_per_socket(void);
extern u32 amd_get_highest_perf(void);
#else
static inline u32 amd_get_nodes_per_socket(void)	{ return 0; }
static inline u32 amd_get_highest_perf(void)		{ return 0; }
#endif

#define for_each_possible_hypervisor_cpuid_base(function) \
	for (function = 0x40000000; function < 0x40010000; function += 0x100)

extern uint32_t hypervisor_cpuid_base(const char *sig, uint32_t leaves);

extern unsigned long arch_align_stack(unsigned long sp);
void free_init_pages(const char *what, unsigned long begin, unsigned long end);
extern void free_kernel_image_pages(const char *what, void *begin, void *end);

void default_idle(void);
#ifdef	CONFIG_XEN
bool xen_set_default_idle(void);
#else
#define xen_set_default_idle 0
#endif

void stop_this_cpu(void *dummy);
void microcode_check(void);

enum l1tf_mitigations {
	L1TF_MITIGATION_OFF,
	L1TF_MITIGATION_FLUSH_NOWARN,
	L1TF_MITIGATION_FLUSH,
	L1TF_MITIGATION_FLUSH_NOSMT,
	L1TF_MITIGATION_FULL,
	L1TF_MITIGATION_FULL_FORCE
};

extern enum l1tf_mitigations l1tf_mitigation;

enum mds_mitigations {
	MDS_MITIGATION_OFF,
	MDS_MITIGATION_FULL,
	MDS_MITIGATION_VMWERV,
};

#endif /* _ASM_X86_PROCESSOR_API_H */
