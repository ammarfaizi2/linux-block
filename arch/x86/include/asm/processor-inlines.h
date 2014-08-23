#ifndef _ASM_X86_PROCESSOR_INLINES_H
#define _ASM_X86_PROCESSOR_INLINES_H

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	/*
	 * This function can be used from the boot code, so it needs
	 * to avoid using EBX in constraints in PIC mode.
	 *
	 * ecx is often an input as well as an output.
	 */
	asm volatile(".ifnc %%ebx,%1 ; .ifnc %%rbx,%1           \n\t"
		     "movl  %%ebx,%1                            \n\t"
		     ".endif ; .endif                           \n\t"
		     "cpuid					\n\t"
		     ".ifnc %%ebx,%1 ; .ifnc %%rbx,%1           \n\t"
		     "xchgl %%ebx,%1                            \n\t"
		     ".endif ; .endif"
	    : "=a" (*eax),
#if defined(__i386__) && defined(__PIC__)
	      "=r" (*ebx),	/* gcc won't let us use ebx */
#else
	      "=b" (*ebx),	/* ebx is okay */
#endif
	      "=c" (*ecx),
	      "=d" (*edx)
	    : "0" (*eax), "2" (*ecx)
	    : "memory");
}

#endif /* _ASM_X86_PROCESSOR_INLINES_H */
