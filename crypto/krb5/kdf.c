// SPDX-License-Identifier: GPL-2.0-or-later
/* Kerberos key derivation.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/slab.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include "internal.h"

/**
 * crypto_krb5_free_enc_keys - Free an encryption keypair
 * @e: The key pair to free.
 */
void crypto_krb5_free_enc_keys(struct krb5_enc_keys *e)
{
	if (e->Ke)
		crypto_free_sync_skcipher(e->Ke);
	if (e->Ki)
		crypto_free_shash(e->Ki);
	e->Ke = NULL;
	e->Ki = NULL;
}
EXPORT_SYMBOL(crypto_krb5_free_enc_keys);

/**
 * crypto_krb5_calc_PRFplus - Calculate PRF+ [RFC4402]
 * @krb5: The encryption type to use
 * @K: The protocol key for the pseudo-random function
 * @L: The length of the output
 * @S: The input octet string
 * @result: Result buffer, sized to krb5->prf_len
 * @gfp: Allocation restrictions
 *
 * Calculate the kerberos pseudo-random function, PRF+() by the following
 * method:
 *
 *      PRF+(K, L, S) = truncate(L, T1 || T2 || .. || Tn)
 *      Tn = PRF(K, n || S)
 *      [rfc4402 sec 2]
 */
int crypto_krb5_calc_PRFplus(const struct krb5_enctype *krb5,
			     const struct krb5_buffer *K,
			     unsigned int L,
			     const struct krb5_buffer *S,
			     struct krb5_buffer *result,
			     gfp_t gfp)
{
	struct krb5_buffer T_series, Tn, n_S;
	void *buffer;
	int ret, n = 1;

	Tn.len = krb5->prf_len;
	T_series.len = 0;
	n_S.len = 4 + S->len;

	buffer = kzalloc(round16(L + Tn.len) + round16(n_S.len), gfp);
	if (!buffer)
		return -ENOMEM;

	T_series.data = buffer;
	n_S.data = buffer + round16(L + Tn.len);
	memcpy(n_S.data + 4, S->data, S->len);

	while (T_series.len < L) {
		*(__be32 *)(n_S.data) = htonl(n);
		Tn.data = T_series.data + Tn.len * (n - 1);
		ret = krb5->profile->calc_PRF(krb5, K, &n_S, &Tn, gfp);
		if (ret < 0)
			goto err;
		T_series.len += Tn.len;
		n++;
	}

	/* Truncate to L */
	memcpy(result->data, T_series.data, L);
	ret = 0;

err:
	kfree_sensitive(buffer);
	return ret;
}
EXPORT_SYMBOL(crypto_krb5_calc_PRFplus);

/**
 * crypto_krb5_get_Kc - Derive key Kc and install into a hash
 * @krb5: The encryption type to use
 * @TK: The base key
 * @usage: The key usage number
 * @key: Prepped buffer to store the key into
 * @_shash: Where to put the hash (or NULL if not wanted)
 * @gfp: Allocation restrictions
 *
 * Derive the Kerberos Kc checksumming key and, optionally, allocate a hash and
 * install the key into it, returning the hash.  The key is stored into the
 * prepared buffer.
 */
int crypto_krb5_get_Kc(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       u32 usage,
		       struct krb5_buffer *key,
		       struct crypto_shash **_shash,
		       gfp_t gfp)
{
	struct crypto_shash *shash;
	int ret;
	u8 buf[CRYPTO_MINALIGN] __aligned(CRYPTO_MINALIGN);
	struct krb5_buffer usage_constant = { .len = 5, .data = buf };

	*(__be32 *)buf = cpu_to_be32(usage);
	buf[4] = KEY_USAGE_SEED_CHECKSUM;

	key->len = krb5->Kc_len;
	ret = krb5->profile->calc_Kc(krb5, TK, &usage_constant, key, gfp);
	if (ret < 0)
		return ret;

	if (_shash) {
		shash = crypto_alloc_shash(krb5->cksum_name, 0, 0);
		if (IS_ERR(shash))
			return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
		*_shash = shash;
		ret = crypto_shash_setkey(shash, key->data, key->len);
	}

	return ret;
}
EXPORT_SYMBOL(crypto_krb5_get_Kc);

/**
 * crypto_krb5_get_Ke - Derive key Ke and install into an skcipher
 * @krb5: The encryption type to use
 * @TK: The base key
 * @usage: The key usage number
 * @key: Prepped buffer to store the key into
 * @_ci: Where to put the cipher (or NULL if not wanted)
 * @gfp: Allocation restrictions
 *
 * Derive the Kerberos Ke encryption key and, optionally, allocate an skcipher
 * and install the key into it, returning the cipher.  The key is stored into
 * the prepared buffer.
 */
int crypto_krb5_get_Ke(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       u32 usage,
		       struct krb5_buffer *key,
		       struct crypto_sync_skcipher **_ci,
		       gfp_t gfp)
{
	struct crypto_sync_skcipher *ci;
	int ret;
	u8 buf[CRYPTO_MINALIGN] __aligned(CRYPTO_MINALIGN);
	struct krb5_buffer usage_constant = { .len = 5, .data = buf };

	*(__be32 *)buf = cpu_to_be32(usage);
	buf[4] = KEY_USAGE_SEED_ENCRYPTION;

	key->len = krb5->Ke_len;
	ret = krb5->profile->calc_Ke(krb5, TK, &usage_constant, key, gfp);
	if (ret < 0)
		return ret;

	if (_ci) {
		ci = crypto_alloc_sync_skcipher(krb5->encrypt_name, 0, 0);
		if (IS_ERR(ci))
			return (PTR_ERR(ci) == -ENOENT) ? -ENOPKG : PTR_ERR(ci);
		*_ci = ci;
		ret = crypto_sync_skcipher_setkey(ci, key->data, key->len);
	}

	return ret;
}
EXPORT_SYMBOL(crypto_krb5_get_Ke);

/**
 * crypto_krb5_get_Ki - Derive key Ki and install into a hash
 * @krb5: The encryption type to use
 * @TK: The base key
 * @usage: The key usage number
 * @key: Prepped buffer to store the key into
 * @_shash: Where to put the hash (or NULL if not wanted)
 * @gfp: Allocation restrictions
 *
 * Derive the Kerberos Ki integrity checksum key and, optionally, allocate a
 * hash and install the key into it, returning the hash.  The key is stored
 * into the prepared buffer.
 */
int crypto_krb5_get_Ki(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       u32 usage,
		       struct krb5_buffer *key,
		       struct crypto_shash **_shash,
		       gfp_t gfp)
{
	struct crypto_shash *shash;
	int ret;
	u8 buf[CRYPTO_MINALIGN] __aligned(CRYPTO_MINALIGN);
	struct krb5_buffer usage_constant = { .len = 5, .data = buf };

	*(__be32 *)buf = cpu_to_be32(usage);
	buf[4] = KEY_USAGE_SEED_INTEGRITY;

	key->len = krb5->Ki_len;
	ret = krb5->profile->calc_Kc(krb5, TK, &usage_constant, key, gfp);
	if (ret < 0)
		return ret;

	if (_shash) {
		shash = crypto_alloc_shash(krb5->cksum_name, 0, 0);
		if (IS_ERR(shash))
			return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
		*_shash = shash;
		ret = crypto_shash_setkey(shash, key->data, key->len);
	}

	return ret;
}
EXPORT_SYMBOL(crypto_krb5_get_Ki);
