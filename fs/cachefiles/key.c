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

/*
 * turn the raw key into something cooked
 * - the key may be up to NAME_MAX in length (including the length word)
 *   - "base64" encode the strange keys, mapping 3 bytes of raw to four of
 *     cooked
 *   - need to cut the cooked key into 252 char lengths (189 raw bytes)
 */
bool cachefiles_cook_key(struct cachefiles_object *object)
{
	const u8 *key = fscache_get_key(object->cookie);
	unsigned int acc, sum, keylen = object->cookie->key_len;
	char *name;
	u8 *buffer, *p;
	int i, len, elem3, print;
	u8 type;

	_enter(",%d", keylen);

	BUG_ON(keylen > NAME_MAX - 3);

	sum = 0;
	print = 1;
	for (i = 0; i < keylen; i++) {
		u8 ch = key[i];
		sum += ch;
		print &= cachefiles_filecharmap[ch];
	}
	object->key_hash = sum;

	/* If the path is usable ASCII, then we render it directly */
	if (print) {
		name = kmalloc(3 + keylen + 1, cachefiles_gfp);
		if (!name)
			return false;

		switch (object->cookie->type) {
		case FSCACHE_COOKIE_TYPE_INDEX:		type = 'I';	break;
		case FSCACHE_COOKIE_TYPE_DATAFILE:	type = 'D';	break;
		default:				type = 'S';	break;
		}

		name[0] = type;
		name[1] = cachefiles_charmap[(keylen >> 6) & 63];
		name[2] = cachefiles_charmap[keylen & 63];

		memcpy(name + 3, key, keylen);
		name[3 + keylen] = 0;
		object->d_name = name;
		object->d_name_len = 3 + keylen;
		goto success;
	}

	/* Construct the key we actually want to render.  We stick the length
	 * on the front and leave NULs on the back for the encoder to overread.
	 */
	buffer = kmalloc(2 + keylen + 3, cachefiles_gfp);
	if (!buffer)
		return false;

	memcpy(buffer + 2, key, keylen);

	*(uint16_t *)buffer = keylen;
	((char *)buffer)[keylen + 2] = 0;
	((char *)buffer)[keylen + 3] = 0;
	((char *)buffer)[keylen + 4] = 0;

	elem3 = DIV_ROUND_UP(2 + keylen, 3); /* Count of 3-byte elements */
	len = elem3 * 4;

	name = kmalloc(1 + len + 1, cachefiles_gfp);
	if (!name) {
		kfree(buffer);
		return false;
	}

	switch (object->cookie->type) {
	case FSCACHE_COOKIE_TYPE_INDEX:		type = 'J';	break;
	case FSCACHE_COOKIE_TYPE_DATAFILE:	type = 'E';	break;
	default:				type = 'T';	break;
	}

	name[0] = type;
	len = 1;
	p = buffer;
	for (i = 0; i < elem3; i++) {
		acc = *p++;
		acc |= *p++ << 8;
		acc |= *p++ << 16;

		name[len++] = cachefiles_charmap[acc & 63];
		acc >>= 6;
		name[len++] = cachefiles_charmap[acc & 63];
		acc >>= 6;
		name[len++] = cachefiles_charmap[acc & 63];
		acc >>= 6;
		name[len++] = cachefiles_charmap[acc & 63];
	}

	name[len] = 0;
	object->d_name = name;
	object->d_name_len = len;
	kfree(buffer);
success:
	_leave(" = %s", object->d_name);
	return true;
}
