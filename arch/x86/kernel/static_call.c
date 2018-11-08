/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/static_call.h>
#include <linux/memory.h>
#include <linux/bug.h>
#include <asm/text-patching.h>
#include <asm/nospec-branch.h>

#define CALL_INSN_SIZE 5

void static_call_bp_handler(void);
void *bp_handler_dest;

#ifdef CONFIG_HAVE_STATIC_CALL_OPTIMIZED

void *bp_handler_continue;

asm(".pushsection .text, \"ax\"						\n"
    ".globl static_call_bp_handler					\n"
    ".type static_call_bp_handler, @function				\n"
    "static_call_bp_handler:						\n"
    "ANNOTATE_RETPOLINE_SAFE						\n"
    "call *bp_handler_dest						\n"
    "ANNOTATE_RETPOLINE_SAFE						\n"
    "jmp *bp_handler_continue						\n"
    ".popsection							\n");

#else /* !CONFIG_HAVE_STATIC_CALL_OPTIMIZED */

asm(".pushsection .text, \"ax\"						\n"
    ".globl static_call_bp_handler					\n"
    ".type static_call_bp_handler, @function				\n"
    "static_call_bp_handler:						\n"
    "ANNOTATE_RETPOLINE_SAFE						\n"
    "jmp *bp_handler_dest						\n"
    ".popsection							\n");

#endif /* !CONFIG_HAVE_STATIC_CALL_OPTIMIZED */

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

	/* Set up the variables for the breakpoint handler: */
	bp_handler_dest = dest;
#ifdef CONFIG_HAVE_STATIC_CALL_OPTIMIZED
	bp_handler_continue = (void *)(insn + CALL_INSN_SIZE);
#endif

	/* Patch the call site: */
	text_poke_bp((void *)insn, opcodes, CALL_INSN_SIZE,
		     static_call_bp_handler);

done:
	mutex_unlock(&text_mutex);
}
EXPORT_SYMBOL_GPL(arch_static_call_transform);

#ifdef CONFIG_HAVE_STATIC_CALL_OPTIMIZED
void arch_static_call_poison_tramp(unsigned long insn)
{
	unsigned long tramp = insn + CALL_INSN_SIZE + *(s32 *)(insn + 1);
	unsigned short opcode = INSN_UD2;

	mutex_lock(&text_mutex);
	text_poke((void *)tramp, &opcode, 2);
	mutex_unlock(&text_mutex);
}
#endif
