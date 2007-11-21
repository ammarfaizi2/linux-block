#ifndef _ASM_X86_INDIRECT_64_H
#define _ASM_X86_INDIRECT_64_H

struct indirect_registers {
	__u64 rax;
	__u64 rdi;
	__u64 rsi;
	__u64 rdx;
	__u64 r10;
	__u64 r8;
	__u64 r9;
};

struct indirect_registers32 {
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
	__u32 esi;
	__u32 edi;
	__u32 ebp;
};

#define INDIRECT_SYSCALL(regs) (regs)->rax
#define INDIRECT_SYSCALL32(regs) (regs)->eax

static inline long call_indirect(struct indirect_registers *regs)
{
  extern long (*sys_call_table[]) (__u64, __u64, __u64, __u64, __u64, __u64);

  return sys_call_table[INDIRECT_SYSCALL(regs)](regs->rdi, regs->rsi,
						regs->rdx, regs->r10,
						regs->r8, regs->r9);
}

#endif
