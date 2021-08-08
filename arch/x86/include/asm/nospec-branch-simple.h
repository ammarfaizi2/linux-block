/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_NOSPEC_BRANCH_SIMPLE_H_
#define _ASM_X86_NOSPEC_BRANCH_SIMPLE_H_

/* Lightweight header for a common definition: */

#define ANNOTATE_RETPOLINE_SAFE					\
	"999:\n\t"						\
	".pushsection .discard.retpoline_safe\n\t"		\
	_ASM_PTR " 999b\n\t"					\
	".popsection\n\t"

#endif /* _ASM_X86_NOSPEC_BRANCH_SIMPLE_H_ */
