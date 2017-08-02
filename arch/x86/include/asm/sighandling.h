#ifndef _ASM_X86_SIGHANDLING_H
#define _ASM_X86_SIGHANDLING_H

#include <linux/compiler.h>
#include <linux/ptrace.h>
#include <linux/signal.h>

#include <asm/processor-flags.h>

#define FIX_EFLAGS	(X86_EFLAGS_AC | X86_EFLAGS_OF | \
			 X86_EFLAGS_DF | X86_EFLAGS_TF | X86_EFLAGS_SF | \
			 X86_EFLAGS_ZF | X86_EFLAGS_AF | X86_EFLAGS_PF | \
			 X86_EFLAGS_CF | X86_EFLAGS_RF)

/* Set up consistently-named typedefs for the user signal types. */
#ifdef CONFIG_X86_64
typedef struct sigcontext sigcontext_t_64;
typedef struct sigframe sigframe_t_64;
typedef struct rt_sigframe rt_sigframe_t_64;
typedef sigset_t sigset_t_64;
#ifdef CONFIG_IA32_EMULATION
typedef struct sigcontext_32 sigcontext_t_32;
typedef struct sigframe_ia32 sigframe_t_32;
typedef struct rt_sigframe_ia32 rt_sigframe_t_32;
typedef compat_sigset_t sigset_t_32;
#define __NR32_sigreturn __NR_ia32_sigreturn
#define __NR32_rt_sigreturn __NR_ia32_rt_sigreturn
#endif
#else
typedef struct sigcontext sigcontext_t_32;
typedef struct sigframe sigframe_t_32;
typedef struct rt_sigframe rt_sigframe_t_32;
typedef sigset_t sigset_t_32;
#define __NR32_sigreturn __NR_sigreturn
#define __NR32_rt_sigreturn __NR_sigreturn_rt
#endif

void signal_fault(struct pt_regs *regs, void __user *frame, char *where);

#ifdef CONFIG_IA32_SUPPORT
int restore_sigcontext_32(struct pt_regs *regs,
			  sigcontext_t_32 __user *sc,
			  unsigned long uc_flags);
int setup_sigcontext_32(sigcontext_t_32 __user *sc, void __user *fpstate,
			struct pt_regs *regs, unsigned long mask);
#endif

#ifdef CONFIG_X86_64
int restore_sigcontext_64(struct pt_regs *regs,
			  sigcontext_t_64 __user *sc,
			  unsigned long uc_flags);
int setup_sigcontext_64(sigcontext_t_64 __user *sc, void __user *fpstate,
			struct pt_regs *regs, unsigned long mask);
void force_valid_ss(struct pt_regs *regs);
#endif

#endif /* _ASM_X86_SIGHANDLING_H */
