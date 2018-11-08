/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/static_call.h>
#include <linux/memory.h>
#include <linux/bug.h>
#include <asm/text-patching.h>
#include <asm/nospec-branch.h>

#define CALL_INSN_SIZE 5

void static_call_bp_handler(void);
void *bp_handler_dest;

asm(".pushsection .text, \"ax\"						\n"
    ".globl static_call_bp_handler					\n"
    ".type static_call_bp_handler, @function				\n"
    "static_call_bp_handler:						\n"
    "ANNOTATE_RETPOLINE_SAFE						\n"
    "jmp *bp_handler_dest						\n"
    ".popsection							\n");

void arch_static_call_transform(unsigned long insn, void *dest)
{
	s32 dest_relative;
	unsigned char insn_opcode;
	unsigned char opcodes[CALL_INSN_SIZE];

	mutex_lock(&text_mutex);

	insn_opcode = *(unsigned char *)insn;
	if (insn_opcode != 0xe8 && insn_opcode != 0xe9) {
		WARN_ONCE(1, "unexpected static call insn opcode 0x%x at %pS",
			  insn_opcode, (void *)insn);
		goto done;
	}

	dest_relative = (long)(dest) - (long)(insn + CALL_INSN_SIZE);

	opcodes[0] = insn_opcode;
	memcpy(&opcodes[1], &dest_relative, CALL_INSN_SIZE - 1);

	/* Set up the variable for the breakpoint handler: */
	bp_handler_dest = dest;

	/* Patch the call site: */
	text_poke_bp((void *)insn, opcodes, CALL_INSN_SIZE,
		     static_call_bp_handler);

done:
	mutex_unlock(&text_mutex);
}
EXPORT_SYMBOL_GPL(arch_static_call_transform);
