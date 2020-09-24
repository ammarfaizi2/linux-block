// SPDX-License-Identifier: GPL-2.0-or-later
/* rfc8009 AES Encryption with HMAC-SHA2 for Kerberos 5
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/key-type.h>
#include <linux/slab.h>
#include <linux/lcm.h>
#include <linux/ctype.h>
#include <linux/sunrpc/gss_krb5.h>
#include <keys/rxrpc-type.h>
#include "ar-internal.h"
#include "rxgk_common.h"

static const struct rxgk_buffer rfc8009_no_context = { .len = 0, .data = "" };

/*
 * Calculate the key derivation function KDF-HMAC-SHA2(key, label, [context,] k)
 *
 *	KDF-HMAC-SHA2(key, label, [context,] k) = k-truncate(K1)
 *
 *	Using the appropriate one of:
 *		K1 = HMAC-SHA-256(key, 0x00000001 | label | 0x00 | k)
 *		K1 = HMAC-SHA-384(key, 0x00000001 | label | 0x00 | k)
 *		K1 = HMAC-SHA-256(key, 0x00000001 | label | 0x00 | context | k)
 *		K1 = HMAC-SHA-384(key, 0x00000001 | label | 0x00 | context | k)
 *	[rfc8009 sec 3]
 */
static int rfc8009_calc_KDF_HMAC_SHA2(const struct rxgk_krb5_enctype *gk5e,
				      const struct rxgk_buffer *key,
				      const struct rxgk_buffer *label,
				      const struct rxgk_buffer *context,
				      unsigned int k,
				      struct rxgk_buffer *result,
				      gfp_t gfp)
{
	struct crypto_shash *shash;
	struct rxgk_buffer K1, data;
	struct shash_desc *desc;
	__be32 tmp;
	size_t bsize;
	void *buffer;
	u8 *p;
	int ret = -ENOMEM;

	_enter("%u,%u,%u,%u,%u", key->len, label->len, context->len, k, result->len);

	if (WARN_ON(result->len != k / 8))
		return -EINVAL;

	shash = crypto_alloc_shash(gk5e->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
	ret = crypto_shash_setkey(shash, key->data, key->len);
	if (ret < 0)
		goto error_shash;

	ret = -EINVAL;
	if (WARN_ON(crypto_shash_digestsize(shash) * 8 < k))
		goto error_shash;

	ret = -ENOMEM;
	data.len = 4 + label->len + 1 + context->len + 4;
	bsize = rxgk_shash_size(shash) +
		rxgk_digest_size(shash) +
		crypto_roundup(data.len);
	buffer = kzalloc(bsize, GFP_NOFS);
	if (!buffer)
		goto error_shash;

	desc = buffer;
	desc->tfm = shash;
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	p = data.data = buffer +
		rxgk_shash_size(shash) +
		rxgk_digest_size(shash);
	*(__be32 *)p = htonl(0x00000001);
	p += 4;
	memcpy(p, label->data, label->len);
	p += label->len;
	*p++ = 0;
	memcpy(p, context->data, context->len);
	p += context->len;
	tmp = htonl(k);
	memcpy(p, &tmp, 4);
	p += 4;

	ret = -EINVAL;
	if (WARN_ON(p - (u8 *)data.data != data.len))
		goto error;

	K1.len = crypto_shash_digestsize(shash);
	K1.data = buffer +
		rxgk_shash_size(shash);

	ret = crypto_shash_finup(desc, data.data, data.len, K1.data);
	if (ret < 0)
		goto error;

	memcpy(result->data, K1.data, result->len);

error:
	kfree_sensitive(buffer);
error_shash:
	crypto_free_shash(shash);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Calculate the pseudo-random function, PRF().
 *
 *	PRF = KDF-HMAC-SHA2(input-key, "prf", octet-string, 256)
 *	PRF = KDF-HMAC-SHA2(input-key, "prf", octet-string, 384)
 *
 *      The "prfconstant" used in the PRF operation is the three-octet string
 *      "prf".
 *      [rfc8009 sec 5]
 */
static int rfc8009_calc_PRF(const struct rxgk_krb5_enctype *gk5e,
			    const struct rxgk_buffer *input_key,
			    const struct rxgk_buffer *octet_string,
			    struct rxgk_buffer *result,
			    gfp_t gfp)
{
	static const struct rxgk_buffer prfconstant = { 3, "prf" };

	return rfc8009_calc_KDF_HMAC_SHA2(gk5e, input_key, &prfconstant,
					  octet_string, gk5e->prf_len * 8,
					  result, gfp);
}

/*
 * Derive Ke.
 *	Ke = KDF-HMAC-SHA2(base-key, usage | 0xAA, 128)
 *	Ke = KDF-HMAC-SHA2(base-key, usage | 0xAA, 256)
 *      [rfc8009 sec 5]
 */
static int rfc8009_calc_Ke(const struct rxgk_krb5_enctype *gk5e,
			   const struct rxgk_buffer *base_key,
			   const struct rxgk_buffer *usage_constant,
			   struct rxgk_buffer *result,
			   gfp_t gfp)
{
	return rfc8009_calc_KDF_HMAC_SHA2(gk5e, base_key, usage_constant,
					  &rfc8009_no_context, gk5e->keybytes * 8,
					  result, gfp);
}

/*
 * Derive Kc/Ki
 *	Kc = KDF-HMAC-SHA2(base-key, usage | 0x99, 128)
 *	Ki = KDF-HMAC-SHA2(base-key, usage | 0x55, 128)
 *	Kc = KDF-HMAC-SHA2(base-key, usage | 0x99, 192)
 *	Ki = KDF-HMAC-SHA2(base-key, usage | 0x55, 192)
 *      [rfc8009 sec 5]
 */
static int rfc8009_calc_Ki(const struct rxgk_krb5_enctype *gk5e,
			   const struct rxgk_buffer *base_key,
			   const struct rxgk_buffer *usage_constant,
			   struct rxgk_buffer *result,
			   gfp_t gfp)
{
	return rfc8009_calc_KDF_HMAC_SHA2(gk5e, base_key, usage_constant,
					  &rfc8009_no_context, gk5e->cksumlength * 8,
					  result, gfp);
}

/*
 * AES random-to-key function.  For AES, this is an identity operation.
 */
static int rfc8009_random_to_key(const struct rxgk_krb5_enctype *gk5e,
				 const struct rxgk_buffer *randombits,
				 struct rxgk_buffer *result)
{
	_enter("");

	if (randombits->len != 16 && randombits->len != 32) {
		_leave(" = -EINVAL [randombits->len is %d]", randombits->len);
		return -EINVAL;
	}

	if (result->len != randombits->len) {
		_leave(" = -EINVAL [len mismatch %u/%u]",
		       result->len, randombits->len);
		return -EINVAL;
	}

	memcpy(result->data, randombits->data, randombits->len);
	_leave(" = 0");
	return 0;
}

static const struct rxgk_crypto_scheme rfc8009_crypto_scheme = {
	.calc_PRF	= rfc8009_calc_PRF,
	.calc_Kc	= rfc8009_calc_Ki,
	.calc_Ke	= rfc8009_calc_Ke,
	.calc_Ki	= rfc8009_calc_Ki,
	.encrypt_skb	= NULL, //rfc8009_encrypt_skb,
	.decrypt_skb	= NULL, //rfc8009_decrypt_skb,
	.get_mic_skb	= rfc3961_get_mic_skb,
	.verify_mic_skb	= rfc3961_verify_mic_skb,
};

const struct rxgk_krb5_enctype rxgk_aes128_cts_hmac_sha256_128 = {
	.etype		= ENCTYPE_AES128_CTS_HMAC_SHA256_128,
	.ctype		= CKSUMTYPE_HMAC_SHA256_128_AES128,
	.name		= "aes128-cts-hmac-sha256-128",
	.encrypt_name	= "cts(cbc(aes))",
	.cksum_name	= "hmac(sha256)",
	.hash_name	= "sha256",
	.keybytes	= 16,
	.keylength	= 16,
	.Kc_len		= 16,
	.Ke_len		= 16,
	.Ki_len		= 16,
	.blocksize	= 16,
	.conflen	= 16,
	.cksumlength	= 16,
	.hashbytes	= 20,
	.prf_len	= 32,
	.keyed_cksum	= true,
	.random_to_key	= rfc8009_random_to_key,
	.scheme		= &rfc8009_crypto_scheme,
};

const struct rxgk_krb5_enctype rxgk_aes256_cts_hmac_sha384_192 = {
	.etype		= ENCTYPE_AES256_CTS_HMAC_SHA384_192,
	.ctype		= CKSUMTYPE_HMAC_SHA384_192_AES256,
	.name		= "aes256-cts-hmac-sha384-192",
	.encrypt_name	= "cts(cbc(aes))",
	.cksum_name	= "hmac(sha384)",
	.hash_name	= "sha384",
	.keybytes	= 32,
	.keylength	= 32,
	.Kc_len		= 24,
	.Ke_len		= 32,
	.Ki_len		= 24,
	.blocksize	= 16,
	.conflen	= 16,
	.cksumlength	= 24,
	.hashbytes	= 20,
	.prf_len	= 48,
	.keyed_cksum	= true,
	.random_to_key	= rfc8009_random_to_key,
	.scheme		= &rfc8009_crypto_scheme,
};
