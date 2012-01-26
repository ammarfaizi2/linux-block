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

#ifdef HAVE_JUMP_LABEL

union jump_code_union {
	char code[JUMP_LABEL_NOP_SIZE];
	struct {
		char jump;
		int offset;
	} __attribute__((packed));
};

static void __jump_label_transform(struct jump_entry *entry,
				   enum jump_label_type type,
				   void *(*poker)(void *, const void *, size_t),
				   int init)
{
	union jump_code_union code;
	const unsigned char *ideal_nop = ideal_nops[NOP_ATOMIC5];

	if (type == JUMP_LABEL_ENABLE) {
		/*
		 * We are enabling this jump label. If it is not a nop
		 * then something must have gone wrong.
		 */
		BUG_ON(memcmp((void *)entry->code, ideal_nop, 5) != 0);

		code.jump = 0xe9;
		code.offset = entry->target -
				(entry->code + JUMP_LABEL_NOP_SIZE);
	} else {
		/*
		 * We are disabling this jump label. If it is not what
		 * we think it is, then something must have gone wrong.
		 * If this is the first initialization call, then we
		 * are converting the default nop to the ideal nop.
		 */
		if (init) {
			unsigned char default_nop[] = { JUMP_LABEL_INIT_NOP };
			BUG_ON(memcmp((void *)entry->code, default_nop, 5) != 0);
		} else {
			code.jump = 0xe9;
			code.offset = entry->target -
				(entry->code + JUMP_LABEL_NOP_SIZE);
			BUG_ON(memcmp((void *)entry->code, &code, 5) != 0);
		}
		memcpy(&code, ideal_nops[NOP_ATOMIC5], JUMP_LABEL_NOP_SIZE);
	}

	(*poker)((void *)entry->code, &code, JUMP_LABEL_NOP_SIZE);
}

void arch_jump_label_transform(struct jump_entry *entry,
			       enum jump_label_type type)
{
	get_online_cpus();
	mutex_lock(&text_mutex);
	__jump_label_transform(entry, type, text_poke_smp, 0);
	mutex_unlock(&text_mutex);
	put_online_cpus();
}

void arch_jump_label_transform_static(struct jump_entry *entry,
				      enum jump_label_type type)
{
	static int once;
	static int update;

	/*
	 * This function is called at boot up and when modules are
	 * first loaded. Check if the default nop, the one that is
	 * inserted at compile time, is the ideal nop. If it is, then
	 * we do not need to update the nop, and we can leave it as is.
	 * If it is not, then we need to update the nop to the ideal nop.
	 */
	if (!once) {
		unsigned char default_nop[] = { JUMP_LABEL_INIT_NOP };
		const unsigned char *ideal_nop = ideal_nops[NOP_ATOMIC5];
		once++;
		if (memcmp(ideal_nop, default_nop, 5) != 0)
			update = 1;
	}
	if (update)
		__jump_label_transform(entry, type, text_poke_early, 1);
}

#endif
