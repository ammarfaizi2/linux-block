/*
 * This file is part of the Linux kernel.
 *
 * Copyright (c) 2014 Andy Lutomirski
 * Authors: Andy Lutomirski <luto@amacapital.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <asm/archrandom.h>
#include <asm/kvm_guest.h>

void arch_rng_init(void *ctx,
		   void (*seed)(void *ctx, u32 data),
		   int bits_per_source,
		   const char *log_prefix)
{
	int i;
	int rdseed_bits = 0, rdrand_bits = 0, kvm_bits = 0;
	bool kvm_seed_works = false;
	char buf[128] = "";
	char *msgptr = buf;

	for (i = 0; i < bits_per_source; i += 8 * sizeof(long)) {
		unsigned long rv;

		if (arch_get_random_seed_long(&rv))
			rdseed_bits += 8 * sizeof(rv);
		else if (arch_get_random_long(&rv))
			rdrand_bits += 8 * sizeof(rv);
		else
			continue;	/* Don't waste time mixing. */

		seed(ctx, (u32)rv);
#if BITS_PER_LONG > 32
		seed(ctx, (u32)(rv >> 32));
#endif
	}

	/*
	 * Use KVM_GET_RNG_SEED regardless of whether the CPU RNG
	 * worked, since it incorporates entropy unavailable to the CPU,
	 * and we shouldn't trust the hardware RNG more than we need to.
	 * We request enough bits for the entire internal RNG state,
	 * because there's no good reason not to.
	 */
	for (i = 0; i < bits_per_source; i += 64) {
		u64 rv;

		if (kvm_get_rng_seed(&rv)) {
			if (rv)
				kvm_seed_works = true;
			seed(ctx, (u32)rv);
			seed(ctx, (u32)(rv >> 32));
			kvm_bits += 8 * sizeof(rv);
		} else {
			break;	/* If it fails once, it will keep failing. */
		}
	}

	if (rdseed_bits)
		msgptr += sprintf(msgptr, ", %d bits from RDSEED", rdseed_bits);
	if (rdrand_bits)
		msgptr += sprintf(msgptr, ", %d bits from RDRAND", rdrand_bits);

	/*
	 * QEMU is buggy and will return all zeros instead of failing.
	 * Don't pretend that it worked if this happens.
	 */
	if (kvm_bits && kvm_seed_works)
		msgptr += sprintf(msgptr, ", %d bits from KVM_GET_RNG_BITS",
				  kvm_bits);

	if (buf[0])
		pr_info("%s with %s\n", log_prefix, buf + 2);
}
