/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ___ASM_SPARC_VDSO_PROCESSOR_H
#define ___ASM_SPARC_VDSO_PROCESSOR_H
#if defined(__sparc__) && defined(__arch64__)
#include <asm/vdso/processor_64.h>
#else
#include <asm/vdso/processor_32.h>
#endif
#endif
