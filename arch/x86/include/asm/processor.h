/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PROCESSOR_H
#define _ASM_X86_PROCESSOR_H

#include <asm/processor_types.h>

#endif /* _ASM_X86_PROCESSOR_H */

#ifndef CONFIG_FAST_HEADERS
# include <asm/cpufeatures.h>
# include <asm/current.h>
# include <asm/desc_defs.h>
# include <asm/fpu/types.h>
# include <asm/ist.h>
# include <asm/math_emu.h>
# include <asm/msr.h>
# include <asm/nops.h>
# include <asm/nospec-branch.h>
# include <asm/page.h>
# include <asm/paravirt.h>
# include <asm/percpu.h>
# include <asm/pgtable_types.h>
# include <asm/processor_api.h>
# include <asm/processor-flags.h>
# include <asm/proto.h>
# include <asm/ptrace.h>
# include <asm/segment.h>
# include <asm/special_insns.h>
# include <asm/types.h>
# include <asm/unwind_hints.h>
# include <asm/vdso/processor.h>
# include <asm/vmxfeatures.h>
# include <linux/apm_bios.h>
# include <linux/cache.h>
# include <linux/cc_platform.h>
# include <linux/edd.h>
# include <linux/err.h>
# include <linux/init.h>
# include <linux/irqflags.h>
# include <linux/math64.h>
# include <linux/mem_encrypt.h>
# include <linux/minmax.h>
# include <linux/personality.h>
# include <linux/screen_info.h>
# include <linux/threads.h>
# include <uapi/asm/sigcontext.h>
#endif
