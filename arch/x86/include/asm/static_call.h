/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STATIC_CALL_H
#define _ASM_STATIC_CALL_H

#ifdef CONFIG_HAVE_STATIC_CALL_OPTIMIZED
/*
 * This is a temporary trampoline which is only used during boot (before the
 * call sites have been patched).  It uses the current value of the key->func
 * pointer to do an indirect jump to the function.
 *
 * The name of this function has a magical aspect.  Objtool uses it to find
 * static call sites so that it can create the .static_call_sites section.
 */
#define ARCH_STATIC_CALL_TEMPORARY_TRAMP(key)				\
	asm(".pushsection .text, \"ax\"				\n"	\
	    ".align 4						\n"	\
	    ".globl " STATIC_CALL_TRAMP_STR(key) "		\n"	\
	    ".type " STATIC_CALL_TRAMP_STR(key) ", @function	\n"	\
	    STATIC_CALL_TRAMP_STR(key) ":			\n"	\
	    ANNOTATE_RETPOLINE_SAFE "				\n"	\
	    "jmpq *" __stringify(key) "(%rip)			\n"	\
	    ".popsection					\n")

#else /* !CONFIG_HAVE_STATIC_CALL_OPTIMIZED */

/*
 * This is a permanent trampoline which is the destination for all static calls
 * for the given key.  The direct jump gets patched by static_call_update().
 */
#define ARCH_STATIC_CALL_TRAMP(key, func)				\
	asm(".pushsection .text, \"ax\"				\n"	\
	    ".align 4						\n"	\
	    ".globl " STATIC_CALL_TRAMP_STR(key) "		\n"	\
	    ".type " STATIC_CALL_TRAMP_STR(key) ", @function	\n"	\
	    STATIC_CALL_TRAMP_STR(key) ":			\n"	\
	    "call " #func "					\n"	\
	    "retq \n"							\
	    ".popsection					\n")


#endif /* !CONFIG_HAVE_STATIC_CALL_OPTIMIZED */

#endif /* _ASM_STATIC_CALL_H */
