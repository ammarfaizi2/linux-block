/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CPUID_H
#define _ASM_X86_CPUID_H

struct cpuid_regs {
	u32 eax, ebx, ecx, edx;
};

enum cpuid_regs_idx {
	CPUID_EAX = 0,
	CPUID_EBX,
	CPUID_ECX,
	CPUID_EDX,
};

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

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
#define __cpuid			native_cpuid
#endif

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

struct cpuid_range_std {
	/* Function 0 */
	u32 max_lvl;
	u32 vendor0, vendor1, vendor2;

	/* Function 1 */
	u32	fms;
	u32	brand_idx : 8, clfsh_lsz : 8, log_cpu_cnt : 8, in_apic_id  : 8;

	/* ecx */
	u32	sse3	  : 1, pclmulqdq : 1, dtes64	  : 1, monitor  : 1,
		dscpl	  : 1, vmx	 : 1, smx	  : 1, eis      : 1,

		tm2	  : 1, ssse3     : 1, cnxt_id	  : 1, sdbg     : 1,
		fma	  : 1, cx16	 : 1, xptr	  : 1, pdcm     : 1,

		__rsvd1	  : 1, pcid	 : 1, dca	  : 1, sse41    : 1,
		sse42	  : 1, x2apic	 : 1, movbe	  : 1, popcnt   : 1,

		tscdeadln : 1, aesni	 : 1, xsave	  : 1, osxsave  : 1,
		avx	  : 1, f16c	 : 1, rdrand	  : 1, hypervsr : 1;

	/* edx */
	u32	fpu	  : 1, vme	 : 1, de	  : 1, pse	: 1,
		tsc	  : 1, msr	 : 1, pae	  : 1, mce      : 1,

		cx8	  : 1, apic	 : 1, __rsvd2	  : 1, sep	: 1,
		mtrr	  : 1, pge	 : 1, mca	  : 1, cmov	: 1,

		pat	  : 1, pse36	 : 1, psn	  : 1, clfsh	: 1,
		__rsvd3	  : 1, ds	 : 1, acpi	  : 1, mmx	: 1,

		fxsr	  : 1, sse	 : 1, sse2	  : 1, ss	: 1,
		htt	  : 1, tm	 : 1,__rsvd4	  : 1, pbe	: 1;
} __packed;

struct cpuid_leafs_info {
        struct cpuid_range_std std;
};

extern struct cpuid_leafs_info cpuid_info;

void cpuid_read_leaf(unsigned int l);
void cpuid_read_all_leafs(void);
#endif /* _ASM_X86_CPUID_H */
