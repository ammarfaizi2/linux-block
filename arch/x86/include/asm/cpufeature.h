/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CPUFEATURE_H
#define _ASM_X86_CPUFEATURE_H


#if defined(__KERNEL__) && !defined(__ASSEMBLY__)

#include <linux/percpu.h>
#include <linux/bitops.h>

#include <asm/vmxfeatures.h>

enum cpuid_leafs
{
	CPUID_1_EDX		= 0,
	CPUID_8000_0001_EDX,
	CPUID_8086_0001_EDX,
	CPUID_LNX_1,
	CPUID_1_ECX,
	CPUID_C000_0001_EDX,
	CPUID_8000_0001_ECX,
	CPUID_LNX_2,
	CPUID_LNX_3,
	CPUID_7_0_EBX,
	CPUID_D_1_EAX,
	CPUID_LNX_4,
	CPUID_7_1_EAX,
	CPUID_8000_0008_EBX,
	CPUID_6_EAX,
	CPUID_8000_000A_EDX,
	CPUID_7_ECX,
	CPUID_8000_0007_EBX,
	CPUID_7_EDX,
	CPUID_8000_001F_EAX,
};

/*
 *  CPU type and hardware bug flags. Kept separately for each CPU.
 *  Members of this structure are referenced in head_32.S, so think twice
 *  before touching them. [mj]
 */

struct cpuinfo_x86 {
	__u8			x86;		/* CPU family */
	__u8			x86_vendor;	/* CPU vendor */
	__u8			x86_model;
	__u8			x86_stepping;
#ifdef CONFIG_X86_64
	/* Number of 4K pages in DTLB/ITLB combined(in pages): */
	int			x86_tlbsize;
#endif
#ifdef CONFIG_X86_VMX_FEATURE_NAMES
	__u32			vmx_capability[NVMXINTS];
#endif
	__u8			x86_virt_bits;
	__u8			x86_phys_bits;
	/* CPUID returned core id bits: */
	__u8			x86_coreid_bits;
	__u8			cu_id;
	/* Max extended CPUID function supported: */
	__u32			extended_cpuid_level;
	/* Maximum supported CPUID level, -1=no CPUID: */
	int			cpuid_level;
	/*
	 * Align to size of unsigned long because the x86_capability array
	 * is passed to bitops which require the alignment. Use unnamed
	 * union to enforce the array is aligned to size of unsigned long.
	 */
	union {
		__u32		x86_capability[NCAPINTS + NBUGINTS];
		unsigned long	x86_capability_alignment;
	};
	char			x86_vendor_id[16];
	char			x86_model_id[64];
	/* in KB - valid for CPUS which support this call: */
	unsigned int		x86_cache_size;
	int			x86_cache_alignment;	/* In bytes */
	/* Cache QoS architectural values, valid only on the BSP: */
	int			x86_cache_max_rmid;	/* max index */
	int			x86_cache_occ_scale;	/* scale to bytes */
	int			x86_cache_mbm_width_offset;
	int			x86_power;
	unsigned long		loops_per_jiffy;
	/* cpuid returned max cores value: */
	u16			x86_max_cores;
	u16			apicid;
	u16			initial_apicid;
	u16			x86_clflush_size;
	/* number of cores as seen by the OS: */
	u16			booted_cores;
	/* Physical processor id: */
	u16			phys_proc_id;
	/* Logical processor id: */
	u16			logical_proc_id;
	/* Core id: */
	u16			cpu_core_id;
	u16			cpu_die_id;
	u16			logical_die_id;
	/* Index into per_cpu list: */
	u16			cpu_index;
	/*  Is SMT active on this core? */
	bool			smt_active;
	u32			microcode;
	/* Address space bits used by the cache internally */
	u8			x86_cache_bits;
	unsigned		initialized : 1;
} __randomize_layout;

/*
 * capabilities of CPUs
 */
extern struct cpuinfo_x86	boot_cpu_data;
extern struct cpuinfo_x86	new_cpu_data;

extern __u32			cpu_caps_cleared[NCAPINTS + NBUGINTS];
extern __u32			cpu_caps_set[NCAPINTS + NBUGINTS];

#ifdef CONFIG_SMP
DECLARE_PER_CPU_READ_MOSTLY(struct cpuinfo_x86, cpu_info);
#define cpu_data(cpu)		per_cpu(cpu_info, cpu)
#else
#define cpu_info		boot_cpu_data
#define cpu_data(cpu)		boot_cpu_data
#endif

extern const struct seq_operations cpuinfo_op;

#define cache_line_size()	(boot_cpu_data.x86_cache_alignment)

extern void cpu_detect(struct cpuinfo_x86 *c);

#define l1tf_pfn_limit() BIT_ULL(boot_cpu_data.x86_cache_bits - 1 - PAGE_SHIFT)

extern void early_cpu_init(void);
extern void identify_boot_cpu(void);
extern void identify_secondary_cpu(struct cpuinfo_x86 *);
extern void print_cpu_info(struct cpuinfo_x86 *);
void print_cpu_msr(struct cpuinfo_x86 *);

#ifdef CONFIG_X86_FEATURE_NAMES
extern const char * const x86_cap_flags[NCAPINTS*32];
extern const char * const x86_power_flags[32];
#define X86_CAP_FMT "%s"
#define x86_cap_flag(flag) x86_cap_flags[flag]
#else
#define X86_CAP_FMT "%d:%d"
#define x86_cap_flag(flag) ((flag) >> 5), ((flag) & 31)
#endif

/*
 * In order to save room, we index into this array by doing
 * X86_BUG_<name> - NCAPINTS*32.
 */
extern const char * const x86_bug_flags[NBUGINTS*32];

#define test_cpu_cap(c, bit)						\
	 test_bit(bit, (unsigned long *)((c)->x86_capability))

/*
 * There are 32 bits/features in each mask word.  The high bits
 * (selected with (bit>>5) give us the word number and the low 5
 * bits give us the bit/feature number inside the word.
 * (1UL<<((bit)&31) gives us a mask for the feature_bit so we can
 * see if it is set in the mask word.
 */
#define CHECK_BIT_IN_MASK_WORD(maskname, word, bit)	\
	(((bit)>>5)==(word) && (1UL<<((bit)&31) & maskname##word ))

/*
 * {REQUIRED,DISABLED}_MASK_CHECK below may seem duplicated with the
 * following BUILD_BUG_ON_ZERO() check but when NCAPINTS gets changed, all
 * header macros which use NCAPINTS need to be changed. The duplicated macro
 * use causes the compiler to issue errors for all headers so that all usage
 * sites can be corrected.
 */
#define REQUIRED_MASK_BIT_SET(feature_bit)		\
	 ( CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  0, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  1, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  2, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  3, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  4, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  5, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  6, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  7, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  8, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK,  9, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 10, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 11, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 12, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 13, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 14, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 15, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 16, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 17, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 18, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(REQUIRED_MASK, 19, feature_bit) ||	\
	   REQUIRED_MASK_CHECK					  ||	\
	   BUILD_BUG_ON_ZERO(NCAPINTS != 20))

#define DISABLED_MASK_BIT_SET(feature_bit)				\
	 ( CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  0, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  1, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  2, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  3, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  4, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  5, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  6, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  7, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  8, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK,  9, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 10, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 11, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 12, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 13, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 14, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 15, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 16, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 17, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 18, feature_bit) ||	\
	   CHECK_BIT_IN_MASK_WORD(DISABLED_MASK, 19, feature_bit) ||	\
	   DISABLED_MASK_CHECK					  ||	\
	   BUILD_BUG_ON_ZERO(NCAPINTS != 20))

#define cpu_has(c, bit)							\
	(__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 :	\
	 test_cpu_cap(c, bit))

#define this_cpu_has(bit)						\
	(__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 :	\
	 x86_this_cpu_test_bit(bit,					\
		(unsigned long __percpu *)&cpu_info.x86_capability))

/*
 * This macro is for detection of features which need kernel
 * infrastructure to be used.  It may *not* directly test the CPU
 * itself.  Use the cpu_has() family if you want true runtime
 * testing of CPU features, like in hypervisor code where you are
 * supporting a possible guest feature where host support for it
 * is not relevant.
 */
#define cpu_feature_enabled(bit)	\
	(__builtin_constant_p(bit) && DISABLED_MASK_BIT_SET(bit) ? 0 : static_cpu_has(bit))

#define boot_cpu_has(bit)	cpu_has(&boot_cpu_data, bit)

#define set_cpu_cap(c, bit)	set_bit(bit, (unsigned long *)((c)->x86_capability))

extern void setup_clear_cpu_cap(unsigned int bit);

struct cpuinfo_x86;
extern void clear_cpu_cap(struct cpuinfo_x86 *c, unsigned int bit);

#define setup_force_cpu_cap(bit) do { \
	set_cpu_cap(&boot_cpu_data, bit);	\
	set_bit(bit, (unsigned long *)cpu_caps_set);	\
} while (0)

#define setup_force_cpu_bug(bit) setup_force_cpu_cap(bit)

#if defined(__clang__) && !defined(CONFIG_CC_HAS_ASM_GOTO)

/*
 * Workaround for the sake of BPF compilation which utilizes kernel
 * headers, but clang does not support ASM GOTO and fails the build.
 */
#ifndef __BPF_TRACING__
#warning "Compiler lacks ASM_GOTO support. Add -D __BPF_TRACING__ to your compiler arguments"
#endif

#define static_cpu_has(bit)            boot_cpu_has(bit)

#else

/*
 * Static testing of CPU features. Used the same as boot_cpu_has(). It
 * statically patches the target code for additional performance. Use
 * static_cpu_has() only in fast paths, where every cycle counts. Which
 * means that the boot_cpu_has() variant is already fast enough for the
 * majority of cases and you should stick to using it as it is generally
 * only two instructions: a RIP-relative MOV and a TEST.
 *
 * Do not use an "m" constraint for [cap_byte] here: gcc doesn't know
 * that this is only used on a fallback path and will sometimes cause
 * it to manifest the address of boot_cpu_data in a register, fouling
 * the mainline (post-initialization) code.
 */
static __always_inline bool _static_cpu_has(u16 bit)
{
	asm_volatile_goto(
		ALTERNATIVE_TERNARY("jmp 6f", %P[feature], "", "jmp %l[t_no]")
		".pushsection .altinstr_aux,\"ax\"\n"
		"6:\n"
		" testb %[bitnum]," _ASM_RIP(%P[cap_byte]) "\n"
		" jnz %l[t_yes]\n"
		" jmp %l[t_no]\n"
		".popsection\n"
		 : : [feature]  "i" (bit),
		     [bitnum]   "i" (1 << (bit & 7)),
		     [cap_byte] "i" (&((const char *)boot_cpu_data.x86_capability)[bit >> 3])
		 : : t_yes, t_no);
t_yes:
	return true;
t_no:
	return false;
}

#define static_cpu_has(bit)					\
(								\
	__builtin_constant_p(boot_cpu_has(bit)) ?		\
		boot_cpu_has(bit) :				\
		_static_cpu_has(bit)				\
)
#endif

#define cpu_has_bug(c, bit)		cpu_has(c, (bit))
#define set_cpu_bug(c, bit)		set_cpu_cap(c, (bit))
#define clear_cpu_bug(c, bit)		clear_cpu_cap(c, (bit))

#define static_cpu_has_bug(bit)		static_cpu_has((bit))
#define boot_cpu_has_bug(bit)		cpu_has_bug(&boot_cpu_data, (bit))
#define boot_cpu_set_bug(bit)		set_cpu_cap(&boot_cpu_data, (bit))

#define MAX_CPU_FEATURES		(NCAPINTS * 32)
#define cpu_have_feature		boot_cpu_has

#define CPU_FEATURE_TYPEFMT		"x86,ven%04Xfam%04Xmod%04X"
#define CPU_FEATURE_TYPEVAL		boot_cpu_data.x86_vendor, boot_cpu_data.x86, \
					boot_cpu_data.x86_model

#endif /* defined(__KERNEL__) && !defined(__ASSEMBLY__) */
#endif /* _ASM_X86_CPUFEATURE_H */
