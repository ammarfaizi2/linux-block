#ifndef _ASM_X86_AUXVEC_H
#define _ASM_X86_AUXVEC_H
/*
 * Architecture-neutral AT_ values in 0-17, leave some room
 * for more of them, start the x86-specific ones at 32.
 */
#ifdef __i386__
#define AT_SYSINFO		32
#endif
#define AT_SYSINFO_EHDR		33
/* 34-36 are AT_xyz_CACHESHAPE on some architectures. */
#define AT_VDSO_FINDSYM		37

/* entries in ARCH_DLINFO: */
#if defined(CONFIG_IA32_EMULATION) || !defined(CONFIG_X86_64)
# define AT_VECTOR_SIZE_ARCH 3
#else /* else it's non-compat x86-64 */
# define AT_VECTOR_SIZE_ARCH 2
#endif

#endif /* _ASM_X86_AUXVEC_H */
