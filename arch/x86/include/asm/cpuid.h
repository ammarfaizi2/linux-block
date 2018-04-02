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

	/* Function 2 */
	u32 tlb_cache[4];

	/* Function 5 */
	u32 lf5_eax, lf5_ebx;

	/* ecx */
	u32	monitor_mwait_enum : 1,
		irq_mwait_break    : 1,
		__rsvd5		   : 30;

	u32 lf5_edx;

	 /* Function 6 */
	u32	lf6_eax;

	u32     dts_num_irqs    : 4,
		__rsvd6        : 28;

	u32     hcfc    : 1, __rsvd7   : 2, peb_pref   : 1,
		__rsvd8 : 28;

	u32     lf6_edx;

	/* Function 7 */
	u32	max_7_subleaf;

	u32	fsgsbase : 1, tsc_adjust : 1, sgx	: 1, bmi1	: 1,
		hle	 : 1, avx2	 : 1, fdp_ex	: 1, smep	: 1,

		bmi2	 : 1, erms	 : 1, invpcid	: 1, rtm	: 1,
		rdtm	 : 1, fpu_cs_ds	 : 1, mpx	: 1, rdta	: 1,

		avx512f	 : 1, avx512dq   : 1, rdseed	: 1, adx	: 1,
		smap	 : 1, avx512ifma : 1, __rsvd9   : 1, clflushopt : 1,

		clwb	 : 1, intelpt	 : 1, avx512pf	: 1, avx512er	: 1,
		avx512cd : 1, sha	 : 1, avx512bw	: 1, avx512vl	: 1;

	u32 prefetchwt1  : 1, avx512_vbmi : 1, umip	: 1, pku	: 1,
		ospke	 : 1, __rsvd10	 : 12, mawau	: 5, rdpid	: 1,
		__rsvd11 : 7, sgx_lc	 : 1, __rsvd12	: 1;

	u32	lf7_edx;

	/* Function 0x15 */
	u32	tsc_ratio_denom, tsc_ratio_num, clock_nom_freq, lfx15_edx;

	/* Function 0x16 */
	union {
		struct {
			u32	base_freq : 16,
				__rsvd13  : 16;
		};
		u32 all;
	} lfx16_eax;

	u32	max_freq  : 16,
		__rsvd14  : 16;
	u32	bus_freq  : 16,
		__rsvd15  : 16;
	u32	lfx16_edx;

} __packed;

struct cpuid_range_ext {
	/* Function 0x8000_0000 */
	u32	max_lvl, vendor0, vendor1, vendor2;

	/* Function 0x8000_0001 */
	union {
		struct {
			u32	stepping  : 4, base_model : 4, base_family : 4, __rsvd0 : 4,
				ext_model : 4, ext_family : 8,			__rsvd1 : 4;
		};
		u32 all;
	} lf1_eax;

	u32	__rsvd2 : 28,
		pkgtype : 4;

	u32	lahfsahf    : 1, cmplegacy	: 1, svm	 : 1, ext_apic_space	: 1,
		alt_mov_cr8 : 1, abm		: 1, sse4a	 : 1, mis_align_sse	: 1,
		_3dnow_pref : 1, osvw		: 1, ibs	 : 1, xop		: 1,
		skinit	    : 1, wdt		: 1, __rsvd3	 : 1, lwp		: 1,
		fma4	    : 1, tce		: 1, __rsvd4	 : 4,
		topoext     : 1, perf_ctr_ext	: 1, __rsvd5	 : 2,
		data_bp_ext : 1, perf_tsc	: 1, perf_ctr_l3 : 1, mwait_ext		: 1,
		__rsvd6: 2;

	u32	fpu	  : 1, vme	: 1, de		: 1, pse	: 1,
		tsc	  : 1, msr	: 1, pae	: 1, mce	: 1,
		cmpxchg8b : 1, apic	: 1, __rsvd7	: 1, syscallret	: 1,
		mtrr	  : 1, pge	: 1, mca	: 1, cmov	: 1,
		pat	  : 1, pse36	: 1, __rsvd8	: 2,
		nx	  : 1, __rsvd9	: 1, mmxext	: 1, mmx	: 1,
		fxsr	  : 1, ffxsr	: 1, page1gb	: 1, rdtscp	: 1,
		__rsvd10  : 1, lm	: 1, _3dnowext	: 1, _3dnow	: 1;

	/* Function 0x8000_0005 */
	union {
		struct {
			u32 l1itlb24msz : 8, l1itlb24mas: 8, l1dtlb24msz: 8, l1dtlb24mas: 8;
		};
		u32 all;
	} lf5_eax;

	u32	l1itlb4ksz : 8, l1itlb4kas : 8, l1dtlb4ksz : 8, l1dtlb4kas : 8;
	u32	l1dclsz    : 8, l1dclntag  : 8, l1dcassoc  : 8, l1dcsz     : 8;
	u32	l1iclsz    : 8, l1iclntag  : 8, l1icassoc  : 8, l1icsz     : 8;
} __packed;



struct cpuid_leafs_info {
        struct cpuid_range_std std;
	struct cpuid_range_ext ext;
};

extern struct cpuid_leafs_info cpuid_info;

void cpuid_read_leaf(unsigned int l);
void cpuid_read_all_leafs(void);
#endif /* _ASM_X86_CPUID_H */
