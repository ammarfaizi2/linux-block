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

void arch_rng_init(void *ctx,
		   void (*seed)(void *ctx, u32 data),
		   int bits_per_source,
		   const char *log_prefix)
{
	int i;
	int rdseed_bits = 0, rdrand_bits = 0;
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

	if (rdseed_bits)
		msgptr += sprintf(msgptr, ", %d bits from RDSEED", rdseed_bits);
	if (rdrand_bits)
		msgptr += sprintf(msgptr, ", %d bits from RDRAND", rdrand_bits);
	if (buf[0])
		pr_info("%s with %s\n", log_prefix, buf + 2);
}
