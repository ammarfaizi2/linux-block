/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PROCESSOR_H
#define _ASM_X86_PROCESSOR_H

/* Forward declaration, a strange C thing */
struct task_struct;
struct mm_struct;
struct io_bitmap;
struct vm86;

#include <linux/bits.h>

#include <asm/desc_defs.h>
#include <asm/msr_types.h>
#include <asm/fpu/types.h>
#include <asm/ptrace_types.h>
#include <asm/segment_types.h>

/*
 * We handle most unaligned accesses in hardware.  On the other hand
 * unaligned DMA can be quite expensive on some Nehalem processors.
 *
 * Based on this we disable the IP header alignment in network drivers.
 */
#define NET_IP_ALIGN	0

#define HBP_NUM 4

/*
 * These alignment constraints are for performance in the vSMP case,
 * but in the task_struct case we must also meet hardware imposed
 * alignment requirements of the FPU state:
 */
#ifdef CONFIG_X86_VSMP
# define ARCH_MIN_TASKALIGN		(1 << INTERNODE_CACHE_SHIFT)
# define ARCH_MIN_MMSTRUCT_ALIGN	(1 << INTERNODE_CACHE_SHIFT)
#else
# define ARCH_MIN_TASKALIGN		__alignof__(union fpregs_state)
# define ARCH_MIN_MMSTRUCT_ALIGN	0
#endif

enum tlb_infos {
	ENTRIES,
	NR_INFO
};

extern u16 tlb_lli_4k[NR_INFO];
extern u16 tlb_lli_2m[NR_INFO];
extern u16 tlb_lli_4m[NR_INFO];
extern u16 tlb_lld_4k[NR_INFO];
extern u16 tlb_lld_2m[NR_INFO];
extern u16 tlb_lld_4m[NR_INFO];
extern u16 tlb_lld_1g[NR_INFO];

struct cpuid_regs {
	u32 eax, ebx, ecx, edx;
};

enum cpuid_regs_idx {
	CPUID_EAX = 0,
	CPUID_EBX,
	CPUID_ECX,
	CPUID_EDX,
};

#define X86_VENDOR_INTEL	0
#define X86_VENDOR_CYRIX	1
#define X86_VENDOR_AMD		2
#define X86_VENDOR_UMC		3
#define X86_VENDOR_CENTAUR	5
#define X86_VENDOR_TRANSMETA	7
#define X86_VENDOR_NSC		8
#define X86_VENDOR_HYGON	9
#define X86_VENDOR_ZHAOXIN	10
#define X86_VENDOR_VORTEX	11
#define X86_VENDOR_NUM		12

#define X86_VENDOR_UNKNOWN	0xff

/*
 * Note that while the legacy 'TSS' name comes from 'Task State Segment',
 * on modern x86 CPUs the TSS also holds information important to 64-bit mode,
 * unrelated to the task-switch mechanism:
 */
#ifdef CONFIG_X86_32
/* This is the TSS defined by the hardware. */
struct x86_hw_tss {
	unsigned short		back_link, __blh;
	unsigned long		sp0;
	unsigned short		ss0, __ss0h;
	unsigned long		sp1;

	/*
	 * We don't use ring 1, so ss1 is a convenient scratch space in
	 * the same cacheline as sp0.  We use ss1 to cache the value in
	 * MSR_IA32_SYSENTER_CS.  When we context switch
	 * MSR_IA32_SYSENTER_CS, we first check if the new value being
	 * written matches ss1, and, if it's not, then we wrmsr the new
	 * value and update ss1.
	 *
	 * The only reason we context switch MSR_IA32_SYSENTER_CS is
	 * that we set it to zero in vm86 tasks to avoid corrupting the
	 * stack if we were to go through the sysenter path from vm86
	 * mode.
	 */
	unsigned short		ss1;	/* MSR_IA32_SYSENTER_CS */

	unsigned short		__ss1h;
	unsigned long		sp2;
	unsigned short		ss2, __ss2h;
	unsigned long		__cr3;
	unsigned long		ip;
	unsigned long		flags;
	unsigned long		ax;
	unsigned long		cx;
	unsigned long		dx;
	unsigned long		bx;
	unsigned long		sp;
	unsigned long		bp;
	unsigned long		si;
	unsigned long		di;
	unsigned short		es, __esh;
	unsigned short		cs, __csh;
	unsigned short		ss, __ssh;
	unsigned short		ds, __dsh;
	unsigned short		fs, __fsh;
	unsigned short		gs, __gsh;
	unsigned short		ldt, __ldth;
	unsigned short		trace;
	unsigned short		io_bitmap_base;

} __attribute__((packed));
#else
struct x86_hw_tss {
	u32			reserved1;
	u64			sp0;
	u64			sp1;

	/*
	 * Since Linux does not use ring 2, the 'sp2' slot is unused by
	 * hardware.  entry_SYSCALL_64 uses it as scratch space to stash
	 * the user RSP value.
	 */
	u64			sp2;

	u64			reserved2;
	u64			ist[7];
	u32			reserved3;
	u32			reserved4;
	u16			reserved5;
	u16			io_bitmap_base;

} __attribute__((packed));
#endif

/*
 * IO-bitmap sizes:
 */
#define IO_BITMAP_BITS			65536
#define IO_BITMAP_BYTES			(IO_BITMAP_BITS / BITS_PER_BYTE)
#define IO_BITMAP_LONGS			(IO_BITMAP_BYTES / sizeof(long))

#define IO_BITMAP_OFFSET_VALID_MAP				\
	(offsetof(struct tss_struct, io_bitmap.bitmap) -	\
	 offsetof(struct tss_struct, x86_tss))

#define IO_BITMAP_OFFSET_VALID_ALL				\
	(offsetof(struct tss_struct, io_bitmap.mapall) -	\
	 offsetof(struct tss_struct, x86_tss))

#ifdef CONFIG_X86_IOPL_IOPERM
/*
 * sizeof(unsigned long) coming from an extra "long" at the end of the
 * iobitmap. The limit is inclusive, i.e. the last valid byte.
 */
# define __KERNEL_TSS_LIMIT	\
	(IO_BITMAP_OFFSET_VALID_ALL + IO_BITMAP_BYTES + \
	 sizeof(unsigned long) - 1)
#else
# define __KERNEL_TSS_LIMIT	\
	(offsetof(struct tss_struct, x86_tss) + sizeof(struct x86_hw_tss) - 1)
#endif

/* Base offset outside of TSS_LIMIT so unpriviledged IO causes #GP */
#define IO_BITMAP_OFFSET_INVALID	(__KERNEL_TSS_LIMIT + 1)

struct entry_stack {
	char	stack[PAGE_SIZE];
};

struct entry_stack_page {
	struct entry_stack stack;
} __aligned(PAGE_SIZE);

/*
 * All IO bitmap related data stored in the TSS:
 */
struct x86_io_bitmap {
	/* The sequence number of the last active bitmap. */
	u64			prev_sequence;

	/*
	 * Store the dirty size of the last io bitmap offender. The next
	 * one will have to do the cleanup as the switch out to a non io
	 * bitmap user will just set x86_tss.io_bitmap_base to a value
	 * outside of the TSS limit. So for sane tasks there is no need to
	 * actually touch the io_bitmap at all.
	 */
	unsigned int		prev_max;

	/*
	 * The extra 1 is there because the CPU will access an
	 * additional byte beyond the end of the IO permission
	 * bitmap. The extra byte must be all 1 bits, and must
	 * be within the limit.
	 */
	unsigned long		bitmap[IO_BITMAP_LONGS + 1];

	/*
	 * Special I/O bitmap to emulate IOPL(3). All bytes zero,
	 * except the additional byte at the end.
	 */
	unsigned long		mapall[IO_BITMAP_LONGS + 1];
};

struct tss_struct {
	/*
	 * The fixed hardware portion.  This must not cross a page boundary
	 * at risk of violating the SDM's advice and potentially triggering
	 * errata.
	 */
	struct x86_hw_tss	x86_tss;

	struct x86_io_bitmap	io_bitmap;
} __aligned(PAGE_SIZE);

struct perf_event;

struct thread_struct {
	/* Cached TLS descriptors: */
	struct desc_struct	tls_array[GDT_ENTRY_TLS_ENTRIES];
#ifdef CONFIG_X86_32
	unsigned long		sp0;
#endif
	unsigned long		sp;
#ifdef CONFIG_X86_32
	unsigned long		sysenter_cs;
#else
	unsigned short		es;
	unsigned short		ds;
	unsigned short		fsindex;
	unsigned short		gsindex;
#endif

#ifdef CONFIG_X86_64
	unsigned long		fsbase;
	unsigned long		gsbase;
#else
	/*
	 * XXX: this could presumably be unsigned short.  Alternatively,
	 * 32-bit kernels could be taught to use fsindex instead.
	 */
	unsigned long fs;
	unsigned long gs;
#endif

	/* Save middle states of ptrace breakpoints */
	struct perf_event	*ptrace_bps[HBP_NUM];
	/* Debug status used for traps, single steps, etc... */
	unsigned long           virtual_dr6;
	/* Keep track of the exact dr7 value set by the user */
	unsigned long           ptrace_dr7;
	/* Fault info: */
	unsigned long		cr2;
	unsigned long		trap_nr;
	unsigned long		error_code;
#ifdef CONFIG_VM86
	/* Virtual 86 mode info */
	struct vm86		*vm86;
#endif
	/* IO permissions: */
	struct io_bitmap	*io_bitmap;

	/*
	 * IOPL. Privilege level dependent I/O permission which is
	 * emulated via the I/O bitmap to prevent user space from disabling
	 * interrupts.
	 */
	unsigned long		iopl_emul;

	unsigned int		iopl_warn:1;
	unsigned int		sig_on_uaccess_err:1;

	/*
	 * Protection Keys Register for Userspace.  Loaded immediately on
	 * context switch. Store it in thread_struct to avoid a lookup in
	 * the tasks's FPU xstate buffer. This value is only valid when a
	 * task is scheduled out. For 'current' the authoritative source of
	 * PKRU is the hardware itself.
	 */
	u32			pkru;

	/* Floating point and extended processor state */
	struct fpu		*fpu;
};

#endif /* _ASM_X86_PROCESSOR_H */
