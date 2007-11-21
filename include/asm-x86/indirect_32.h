#ifndef _ASM_X86_INDIRECT_32_H
#define _ASM_X86_INDIRECT_32_H

struct indirect_registers {
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
	__u32 esi;
	__u32 edi;
	__u32 ebp;
};

#define INDIRECT_SYSCALL(regs) (regs)->eax

static inline long call_indirect(struct indirect_registers *regs)
{
  extern long (*sys_call_table[]) (__u32, __u32, __u32, __u32, __u32, __u32);

  return sys_call_table[INDIRECT_SYSCALL(regs)](regs->ebx, regs->ecx,
						regs->edx, regs->esi,
						regs->edi, regs->ebp);
}

#endif
