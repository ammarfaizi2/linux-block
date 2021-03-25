// SPDX-License-Identifier: GPL-2.0-or-later
/* Key to pathname encoder
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/slab.h>
#include "internal.h"

static const char cachefiles_charmap[64] =
	"0123456789"			/* 0 - 9 */
	"abcdefghijklmnopqrstuvwxyz"	/* 10 - 35 */
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"	/* 36 - 61 */
	"_-"				/* 62 - 63 */
	;

static const char cachefiles_filecharmap[256] = {
	/* we skip space and tab and control chars */
	[33 ... 46] = 1,		/* '!' -> '.' */
	/* we skip '/' as it's significant to pathwalk */
	[48 ... 127] = 1,		/* '0' -> '~' */
};

static inline unsigned int how_many_hex_digits(unsigned int x)
{
	return x ? round_up(ilog2(x) + 1, 4) / 4: 0;
}

/*
 * turn the raw key into something cooked
 * - the raw key should include the length in the two bytes at the front
 * - the key may be up to 514 bytes in length (including the length word)
 *   - "base64" encode the strange keys, mapping 3 bytes of raw to four of
 *     cooked
 *   - need to cut the cooked key into 252 char lengths (189 raw bytes)
 */
char *cachefiles_cook_key(const u8 *raw, int keylen, u8 *_sum)
{
	unsigned char sum, ch;
	unsigned int acc, i, n, nle, nbe;
	char *key, *p, sep;
	int b64len, len, seg, print;

	_enter(",%d", keylen);

	BUG_ON(keylen < 2 || keylen > 514);

	sum = raw[0] + raw[1];
	print = 1;
	for (i = 2; i < keylen; i++) {
		ch = raw[i];
		sum += ch;
		print &= cachefiles_filecharmap[ch];
	}
	*_sum = sum;

	/* If the path is usable ASCII, then render it directly */
	if (print) {
		key = kmalloc(keylen + 3, cachefiles_gfp);
		if (key) {
			key[0] = 'D'; /* Data object type */
			key[1] = 'A'; /* Encoding indicator */
			key[keylen + 2] = 0;
			memcpy(key + 2, raw, keylen);
		}
		_leave(" = %s", key);
		return key;
	}

	/* See if it makes sense to encode it as "hex,hex,hex" for each 32-bit chunk */
	n = round_up(keylen, 4);
	nbe = nle = 1;
	for (i = 0; i < n; i += 4) {
		u32 be;
		u32 le;

		be = be32_to_cpu(*(__be32 *)(raw + i));
		le = le32_to_cpu(*(__le32 *)(raw + i));

		nbe += 1 + how_many_hex_digits(be);
		nle += 1 + how_many_hex_digits(le);
	}

	b64len = 2 + ((keylen + 2) / 3) * 4; /* Length if we base64-encode it */
	_debug("len=%u nbe=%u nle=%u b64=%u", keylen, nbe, nle, b64len);
	if (nbe < b64len || nle < b64len) {
		len = min(nbe, nle) + 1;
		key = kmalloc(len, cachefiles_gfp);
		if (!key)
			return NULL;
		sep = (nbe <= nle) ? 'B' : 'L'; /* Encoding indicator */
		p = key;
		*p++ = 'D';
		for (i = 0; i < n; i += 4) {
			u32 x;
			if (nbe <= nle)
				x = be32_to_cpu(*(__be32 *)(raw + i));
			else
				x = le32_to_cpu(*(__le32 *)(raw + i));
			if (x == 0) {
				*p = sep;
				seg = 1;
			} else {
				seg = snprintf(p, len, "%c%x", sep, x);
			}
			p += seg;
			len -= seg;
			sep = ',';
		}
		*p = 0;
		_leave(" = %s", key);
		return key;
	}

	/* We need to base64-encode it */
	key = kmalloc(b64len + 1, cachefiles_gfp);
	if (!key)
		return NULL;

	p = key;
	*p++ = 'D';
	*p++ = '%';
	len = 1;

	for (i = (keylen + 2) / 3; i > 0; i--) {
		acc = *raw++;
		acc |= *raw++ << 8;
		acc |= *raw++ << 16;

		_debug("acc: %06x", acc);

		*p++ = cachefiles_charmap[acc & 63];
		acc >>= 6;
		*p++ = cachefiles_charmap[acc & 63];
		acc >>= 6;
		*p++ = cachefiles_charmap[acc & 63];
		acc >>= 6;
		*p++ = cachefiles_charmap[acc & 63];
	}
	ASSERTCMP(p, ==, key + b64len);

	*p = 0;
	_leave(" = %s", key);
	return key;
}
