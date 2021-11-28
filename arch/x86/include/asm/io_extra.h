/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_IO_EXTRA_H
#define _ASM_X86_IO_EXTRA_H

#include <asm/io.h>

#include <asm/special_insns.h>

/**
 * iosubmit_cmds512 - copy data to single MMIO location, in 512-bit units
 * @dst: destination, in MMIO space (must be 512-bit aligned)
 * @src: source
 * @count: number of 512 bits quantities to submit
 *
 * Submit data from kernel space to MMIO space, in units of 512 bits at a
 * time.  Order of access is not guaranteed, nor is a memory barrier
 * performed afterwards.
 *
 * Warning: Do not use this helper unless your driver has checked that the CPU
 * instruction is supported on the platform.
 */
static inline void iosubmit_cmds512(void __iomem *dst, const void *src,
				    size_t count)
{
	const u8 *from = src;
	const u8 *end = from + count * 64;

	while (from < end) {
		movdir64b(dst, from);
		from += 64;
	}
}

#endif /* _ASM_X86_IO_EXTRA_H */
