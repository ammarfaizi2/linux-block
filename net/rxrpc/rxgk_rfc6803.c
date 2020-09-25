// SPDX-License-Identifier: GPL-2.0-or-later
/* rfc6803 Camellia Encryption for Kerberos 5
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

/*
 * Calculate the key derivation function KDF-FEEDBACK_CMAC(key, constant)
 *
 *	n = ceiling(k / 128)
 *	K(0) = zeros
 *	K(i) = CMAC(key, K(i-1) | i | constant | 0x00 | k)
 *	DR(key, constant) = k-truncate(K(1) | K(2) | ... | K(n))
 *	KDF-FEEDBACK-CMAC(key, constant) = random-to-key(DR(key, constant))
 *
 *	[rfc6803 sec 3]
 */
static int rfc6803_calc_KDF_FEEDBACK_CMAC(const struct rxgk_krb5_enctype *gk5e,
					  const struct rxgk_buffer *key,
					  const struct rxgk_buffer *constant,
					  struct rxgk_buffer *result,
					  gfp_t gfp)
{
	struct crypto_shash *shash;
	struct rxgk_buffer K, data;
	struct shash_desc *desc;
	__be32 tmp;
	size_t bsize, offset, seg;
	void *buffer;
	u32 i = 0, k = result->len * 8;
	u8 *p;
	int ret = -ENOMEM;

	_enter("%u,%u,%u", key->len, constant->len, result->len);

	shash = crypto_alloc_shash(gk5e->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
	ret = crypto_shash_setkey(shash, key->data, key->len);
	if (ret < 0)
		goto error_shash;

	ret = -ENOMEM;
	K.len = crypto_shash_digestsize(shash);
	data.len = K.len + 4 + constant->len + 1 + 4;
	bsize = rxgk_shash_size(shash) +
		rxgk_digest_size(shash) +
		crypto_roundup(K.len) +
		crypto_roundup(data.len);
	buffer = kzalloc(bsize, GFP_NOFS);
	if (!buffer)
		goto error_shash;

	desc = buffer;
	desc->tfm = shash;

	K.data = buffer +
		rxgk_shash_size(shash) +
		rxgk_digest_size(shash);
	data.data = buffer +
		rxgk_shash_size(shash) +
		rxgk_digest_size(shash) +
		crypto_roundup(K.len);

	p = data.data + K.len + 4;
	memcpy(p, constant->data, constant->len);
	p += constant->len;
	*p++ = 0x00;
	tmp = htonl(k);
	memcpy(p, &tmp, 4);
	p += 4;

	ret = -EINVAL;
	if (WARN_ON(p - (u8 *)data.data != data.len))
		goto error;

	offset = 0;
	do {
		i++;
		p = data.data;
		memcpy(p, K.data, K.len);
		p += K.len;
		*(__be32 *)p = htonl(i);

		ret = crypto_shash_init(desc);
		if (ret < 0)
			goto error;
		ret = crypto_shash_finup(desc, data.data, data.len, K.data);
		if (ret < 0)
			goto error;

		seg = min_t(size_t, result->len - offset, K.len);
		memcpy(result->data + offset, K.data, seg);
		offset += seg;
	} while (offset < result->len);

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
 *	Kp = KDF-FEEDBACK-CMAC(protocol-key, "prf")
 *	PRF = CMAC(Kp, octet-string)
 *      [rfc6803 sec 6]
 */
static int rfc6803_calc_PRF(const struct rxgk_krb5_enctype *gk5e,
			    const struct rxgk_buffer *protocol_key,
			    const struct rxgk_buffer *octet_string,
			    struct rxgk_buffer *result,
			    gfp_t gfp)
{
	static const struct rxgk_buffer prfconstant = { 3, "prf" };
	struct crypto_shash *shash;
	struct rxgk_buffer Kp;
	struct shash_desc *desc;
	size_t bsize;
	void *buffer;
	int ret;

	_enter("%u,%u,%u", protocol_key->len, octet_string->len, result->len);

	Kp.len = gk5e->prf_len;

	shash = crypto_alloc_shash(gk5e->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);

	ret = -EINVAL;
	if (result->len != crypto_shash_digestsize(shash)) {
		pr_warn("size mismatch %u %u\n", result->len,
			crypto_shash_digestsize(shash));
		goto out_shash;
	}

	ret = -ENOMEM;
	bsize = rxgk_shash_size(shash) +
		rxgk_digest_size(shash) +
		crypto_roundup(Kp.len);
	buffer = kzalloc(bsize, GFP_NOFS);
	if (!buffer)
		goto out_shash;

	Kp.data = buffer +
		rxgk_shash_size(shash) +
		rxgk_digest_size(shash);

	ret = rfc6803_calc_KDF_FEEDBACK_CMAC(gk5e, protocol_key, &prfconstant,
					     &Kp, gfp);
	if (ret < 0)
		goto out;

	ret = crypto_shash_setkey(shash, Kp.data, Kp.len);
	if (ret < 0)
		goto out;

	desc = buffer;
	desc->tfm = shash;
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto out;

	ret = crypto_shash_finup(desc, octet_string->data, octet_string->len, result->data);
	if (ret < 0)
		goto out;

out:
	kfree_sensitive(buffer);
out_shash:
	crypto_free_shash(shash);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Camellia random-to-key function.  This is an identity operation.
 */
static int rfc6803_random_to_key(const struct rxgk_krb5_enctype *gk5e,
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

static const struct rxgk_crypto_scheme rfc6803_crypto_scheme = {
	.calc_PRF	= rfc6803_calc_PRF,
	.calc_Kc	= rfc6803_calc_KDF_FEEDBACK_CMAC,
	.calc_Ke	= rfc6803_calc_KDF_FEEDBACK_CMAC,
	.calc_Ki	= rfc6803_calc_KDF_FEEDBACK_CMAC,
	.encrypt_skb	= rfc3961_encrypt_skb,
	.decrypt_skb	= rfc3961_decrypt_skb,
	.get_mic_skb	= rfc3961_get_mic_skb,
	.verify_mic_skb	= rfc3961_verify_mic_skb,
};

const struct rxgk_krb5_enctype rxgk_camellia128_cts_cmac = {
	.etype		= ENCTYPE_CAMELLIA128_CTS_CMAC,
	.ctype		= CKSUMTYPE_CMAC_CAMELLIA128,
	.name		= "camellia128-cts-cmac",
	.encrypt_name	= "cts(cbc(camellia))",
	.cksum_name	= "cmac(camellia)",
	.hash_name	= NULL,
	.keybytes	= 16,
	.keylength	= 16,
	.Kc_len		= 16,
	.Ke_len		= 16,
	.Ki_len		= 16,
	.blocksize	= 16,
	.conflen	= 16,
	.cksumlength	= 16,
	.hashbytes	= 16,
	.prf_len	= 16,
	.keyed_cksum	= true,
	.random_to_key	= rfc6803_random_to_key,
	.scheme		= &rfc6803_crypto_scheme,
};

const struct rxgk_krb5_enctype rxgk_camellia256_cts_cmac = {
	.etype		= ENCTYPE_CAMELLIA256_CTS_CMAC,
	.ctype		= CKSUMTYPE_CMAC_CAMELLIA256,
	.name		= "camellia256-cts-cmac",
	.encrypt_name	= "cts(cbc(camellia))",
	.cksum_name	= "cmac(camellia)",
	.hash_name	= NULL,
	.keybytes	= 32,
	.keylength	= 32,
	.Kc_len		= 32,
	.Ke_len		= 32,
	.Ki_len		= 32,
	.blocksize	= 16,
	.conflen	= 16,
	.cksumlength	= 16,
	.hashbytes	= 16,
	.prf_len	= 16,
	.keyed_cksum	= true,
	.random_to_key	= rfc6803_random_to_key,
	.scheme		= &rfc6803_crypto_scheme,
};
