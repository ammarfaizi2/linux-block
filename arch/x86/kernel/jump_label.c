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

/* These are the nops added at compile time */
static const unsigned char nop_short[] = { P6_NOP2 };
static const unsigned char default_nop[] = { JUMP_LABEL_INIT_NOP };

union jump_code_union {
	char code[JUMP_LABEL_NOP_SIZE];
	struct {
		char jump;
		int offset;
	} __packed;
	struct {
		char jump_short;
		char offset_short;
	} __packed;
};

static void __jump_label_transform(struct jump_entry *entry,
				   enum jump_label_type type,
				   void *(*poker)(void *, const void *, size_t),
				   int init)
{
	union jump_code_union code;
	unsigned char nop;
	unsigned char op;
	unsigned size;
	void *ip = (void *)entry->code;
	const unsigned char *ideal_nop = ideal_nops[NOP_ATOMIC5];

	/* Use probe_kernel_read()? */
	op = *(unsigned char *)ip;
	nop = ideal_nops[NOP_ATOMIC5][0];

	if (type == JUMP_LABEL_ENABLE) {
		if (memcmp(ip, nop_short, 2) == 0) {
			size = 2;
			code.jump_short = 0xeb;
			code.offset = entry->target - (entry->code + 2);
			/* Check for overflow ? */
		} else if (memcmp(ip, ideal_nop, 5) == 0) {
			size = JUMP_LABEL_NOP_SIZE;
			code.jump = 0xe9;
			code.offset = entry->target - (entry->code + size);
		} else
			/*
			 * The location is not a nop that we were expecting,
			 * something went wrong. Crash the box, as something could be
			 * corrupting the kernel.
			 */
			BUG();
	} else {
		/*
		 * We are disabling this jump label. If it is not what
		 * we think it is, then something must have gone wrong.
		 * If this is the first initialization call, then we
		 * are converting the default nop to the ideal nop.
		 */
		if (init) {
			/* Ignore short nops, we do not change them */
			if (memcmp(ip, nop_short, 2) == 0)
				return;

			/* We are initializing from the default nop */
			BUG_ON(memcmp(ip, default_nop, 5) != 0);

			/* Set to the ideal nop */
			size = JUMP_LABEL_NOP_SIZE;
			memcpy(&code, ideal_nops[NOP_ATOMIC5], size);

		} else if (op == 0xe9) {
			/* Replace a 5 byte jmp */

			/* Make sure this is what we expected it to be */
			code.jump = 0xe9;
			code.offset = entry->target -
				(entry->code + JUMP_LABEL_NOP_SIZE);
			BUG_ON(memcmp(ip, &code, 5) != 0);

			size = JUMP_LABEL_NOP_SIZE;
			memcpy(&code, ideal_nops[NOP_ATOMIC5], size);
		} else if (op == 0xeb) {
			/* Replace a 2 byte jmp */

			/* Had better be a 2 byte jmp */
			code.jump_short = 0xeb;
			code.offset = entry->target - (entry->code + 2);
			BUG_ON(memcmp(ip, &code, 2) != 0);

			size = 2;
			memcpy(&code, nop_short, size);
		} else
			/* The code was not what we expected!  */
			BUG();
	}

	(*poker)(ip, &code, size);
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
		const unsigned char *ideal_nop = ideal_nops[NOP_ATOMIC5];
		once++;
		if (memcmp(ideal_nop, default_nop, 5) != 0)
			update = 1;
	}
	if (update)
		__jump_label_transform(entry, type, text_poke_early, 1);
}
#endif
