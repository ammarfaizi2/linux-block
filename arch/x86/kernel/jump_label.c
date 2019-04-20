// SPDX-License-Identifier: GPL-2.0
/*
 * jump label x86 support
 *
 * Copyright (C) 2009 Jason Baron <jbaron@redhat.com>
 *
 */
#include <linux/jump_label.h>
#include <linux/memory.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/cpu.h>
#include <asm/kprobes.h>
#include <asm/alternative.h>
#include <asm/text-patching.h>
#include <linux/slab.h>

union jump_code_union {
	char code[JUMP_LABEL_NOP_SIZE];
	struct {
		char jump;
		int offset;
	} __attribute__((packed));
};

static void bug_at(unsigned char *ip, int line)
{
	/*
	 * The location is not an op that we were expecting.
	 * Something went wrong. Crash the box, as something could be
	 * corrupting the kernel.
	 */
	pr_crit("jump_label: Fatal kernel bug, unexpected op at %pS [%p] (%5ph) %d\n", ip, ip, ip, line);
	BUG();
}

static inline void __jump_label_trans_check_enable(struct jump_entry *entry,
						   enum jump_label_type type,
						   const unsigned char *ideal_nop,
						   int init)
{
	const unsigned char default_nop[] = { STATIC_KEY_INIT_NOP };
	const void *expect;
	int line;

	if (init) {
		expect = default_nop; line = __LINE__;
	} else {
		expect = ideal_nop; line = __LINE__;
	}

	if (memcmp((void *)jump_entry_code(entry), expect, JUMP_LABEL_NOP_SIZE))
		bug_at((void *)jump_entry_code(entry), line);
}

static inline void __jump_label_trans_check_disable(struct jump_entry *entry,
						    enum jump_label_type type,
						    union jump_code_union *jmp,
						    int init)
{
	const unsigned char default_nop[] = { STATIC_KEY_INIT_NOP };
	const void *expect;
	int line;

	if (init) {
		expect = default_nop; line = __LINE__;
	} else {
		expect = jmp->code; line = __LINE__;
	}

	if (memcmp((void *)jump_entry_code(entry), expect, JUMP_LABEL_NOP_SIZE))
		bug_at((void *)jump_entry_code(entry), line);
}

static void __jump_label_set_jump_code(struct jump_entry *entry,
				       enum jump_label_type type,
				       union jump_code_union *code,
				       int init)
{
	const unsigned char *ideal_nop = ideal_nops[NOP_ATOMIC5];

	code->jump = 0xe9;
	code->offset = jump_entry_target(entry) -
		     (jump_entry_code(entry) + JUMP_LABEL_NOP_SIZE);

	if (type == JUMP_LABEL_JMP) {
		__jump_label_trans_check_enable(entry, type, ideal_nop, init);
	} else {
		__jump_label_trans_check_disable(entry, type, code, init);
		memcpy(code, ideal_nop, JUMP_LABEL_NOP_SIZE);
	}
}

static void __ref __jump_label_transform(struct jump_entry *entry,
					 enum jump_label_type type,
					 void *(*poker)(void *, const void *, size_t),
					 int init)
{
	union jump_code_union code;

	if (early_boot_irqs_disabled)
		poker = text_poke_early;

	__jump_label_set_jump_code(entry, type, &code, init);

	/*
	 * Make text_poke_bp() a default fallback poker.
	 *
	 * At the time the change is being done, just ignore whether we
	 * are doing nop -> jump or jump -> nop transition, and assume
	 * always nop being the 'currently valid' instruction
	 *
	 */
	if (poker) {
		(*poker)((void *)jump_entry_code(entry), &code,
			 JUMP_LABEL_NOP_SIZE);
		return;
	}

	text_poke_bp((void *)jump_entry_code(entry), &code, JUMP_LABEL_NOP_SIZE,
		     (void *)jump_entry_code(entry) + JUMP_LABEL_NOP_SIZE);
}

void arch_jump_label_transform(struct jump_entry *entry,
			       enum jump_label_type type)
{
	mutex_lock(&text_mutex);
	__jump_label_transform(entry, type, NULL, 0);
	mutex_unlock(&text_mutex);
}

struct text_to_poke *entry_vector;
unsigned int entry_vector_max_elem __read_mostly;
unsigned int entry_vector_nr_elem;

void arch_jump_label_init(void)
{
	entry_vector = (void *) __get_free_page(GFP_KERNEL);

	if (WARN_ON_ONCE(!entry_vector))
		return;

	entry_vector_max_elem = PAGE_SIZE / sizeof(struct text_to_poke);
	return;
}

int arch_jump_label_transform_queue(struct jump_entry *entry,
				     enum jump_label_type type)
{
	void *entry_code;
	struct text_to_poke *tp;

	/*
	 * Batch mode disabled before being able to allocate memory:
	 * Fallback to the non-batching mode.
	 */
	if (unlikely(!entry_vector_max_elem)) {
		if (!slab_is_available() || early_boot_irqs_disabled)
			goto fallback;

		arch_jump_label_init();
	}

	/*
	 * No more space in the vector, tell upper layer to apply
	 * the queue before continuing.
	 */
	if (entry_vector_nr_elem == entry_vector_max_elem)
		return 0;

	tp = &entry_vector[entry_vector_nr_elem];

	entry_code = (void *)jump_entry_code(entry);

	/*
	 * The int3 handler will do a bsearch in the queue, so we need entries
	 * to be sorted. We can survive an unsorted list by rejecting the entry,
	 * forcing the generic jump_label code to apply the queue. Warning once,
	 * to raise the attention to the case of an unsorted entry that is
	 * better not happen, because, in the worst case we will perform in the
	 * same way as we do without batching - with some more overhead.
	 */
	if (entry_vector_nr_elem > 0) {
		int prev_idx = entry_vector_nr_elem - 1;
		struct text_to_poke *prev_tp = &entry_vector[prev_idx];

		if (WARN_ON_ONCE(prev_tp->addr > entry_code))
			return 0;
	}

	__jump_label_set_jump_code(entry, type,
				   (union jump_code_union *) &tp->opcode, 0);

	tp->addr = entry_code;
	tp->handler = entry_code + JUMP_LABEL_NOP_SIZE;
	tp->len = JUMP_LABEL_NOP_SIZE;

	entry_vector_nr_elem++;

	return 1;

fallback:
	arch_jump_label_transform(entry, type);
	return 1;
}

void arch_jump_label_transform_apply(void)
{
	if (early_boot_irqs_disabled || !entry_vector_nr_elem)
		return;

	mutex_lock(&text_mutex);
	text_poke_bp_batch(entry_vector, entry_vector_nr_elem);
	mutex_unlock(&text_mutex);

	entry_vector_nr_elem = 0;
}

static enum {
	JL_STATE_START,
	JL_STATE_NO_UPDATE,
	JL_STATE_UPDATE,
} jlstate __initdata_or_module = JL_STATE_START;

__init_or_module void arch_jump_label_transform_static(struct jump_entry *entry,
				      enum jump_label_type type)
{
	/*
	 * This function is called at boot up and when modules are
	 * first loaded. Check if the default nop, the one that is
	 * inserted at compile time, is the ideal nop. If it is, then
	 * we do not need to update the nop, and we can leave it as is.
	 * If it is not, then we need to update the nop to the ideal nop.
	 */
	if (jlstate == JL_STATE_START) {
		const unsigned char default_nop[] = { STATIC_KEY_INIT_NOP };
		const unsigned char *ideal_nop = ideal_nops[NOP_ATOMIC5];

		if (memcmp(ideal_nop, default_nop, 5) != 0)
			jlstate = JL_STATE_UPDATE;
		else
			jlstate = JL_STATE_NO_UPDATE;
	}
	if (jlstate == JL_STATE_UPDATE)
		__jump_label_transform(entry, type, text_poke_early, 1);
}
