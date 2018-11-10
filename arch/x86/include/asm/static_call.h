/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_STATIC_CALL_H
#define _ASM_STATIC_CALL_H

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

#endif /* _ASM_STATIC_CALL_H */
