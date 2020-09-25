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

/*
 * Apply encryption and checksumming functions to part of an skbuff.
 */
static int rfc8009_encrypt_skb(const struct rxgk_krb5_enctype *gk5e,
			       struct rxgk_enc_keys *keys,
			       struct sk_buff *skb,
			       u16 data_offset, u16 data_len,
			       bool preconfounded)
{
	struct skcipher_request	*req;
	struct scatterlist sg[16];
	struct shash_desc *desc;
	unsigned short base_len, secure_offset, secure_len, pad_len, cksum_offset;
	size_t bsize;
	void *buffer;
	int ret;
	u8 *cksum, *iv;

	_enter("{%x},%x,%x", skb->len, data_offset, data_len);

	if (WARN_ON(data_offset < gk5e->conflen))
		return -EMSGSIZE;

	base_len   = gk5e->conflen + data_len;
	secure_len = base_len;
	pad_len    = secure_len - base_len;
	secure_offset = data_offset - gk5e->conflen;
	cksum_offset = secure_offset + secure_len;

	bsize = rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki) +
		rxgk_sync_skcipher_size(keys->Ke) +
		rxgk_sync_skcipher_ivsize(keys->Ke);
	bsize = max_t(size_t, bsize, gk5e->conflen);
	bsize = max_t(size_t, bsize, gk5e->blocksize);
	buffer = kzalloc(bsize, GFP_NOFS);
	if (!buffer)
		return -ENOMEM;

	/* Insert the confounder into the skb */
	if (!preconfounded) {
		get_random_bytes(buffer, gk5e->conflen);
		ret = skb_store_bits(skb, secure_offset, buffer, gk5e->conflen);
		if (ret < 0)
			goto error;
	}

	/* We need to pad out to the crypto blocksize. */
	if (pad_len) {
		memset(buffer, 0, pad_len);
		ret = skb_store_bits(skb, data_offset + data_len, buffer, pad_len);
		if (ret < 0)
			goto error;
	}

	/* Set up an s-g list to cover the encryptable region. */
	sg_init_table(sg, ARRAY_SIZE(sg));
	ret = skb_to_sgvec(skb, sg, secure_offset, secure_len);
	if (unlikely(ret < 0))
		goto error;

	/* Encrypt the secure region with key Ke. */
	req = buffer +
		rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki);
	iv = buffer +
		rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki) +
		rxgk_sync_skcipher_size(keys->Ke);

	skcipher_request_set_sync_tfm(req, keys->Ke);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, sg, sg, secure_len, iv);
	ret = crypto_skcipher_encrypt(req);
	if (ret < 0)
		goto error;

	/* Calculate the checksum using key Ki */
	cksum = buffer + rxgk_shash_size(keys->Ki);

	desc = buffer;
	desc->tfm = keys->Ki;
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	memset(iv, 0, crypto_sync_skcipher_ivsize(keys->Ke));
	ret = crypto_shash_update(desc, iv, crypto_sync_skcipher_ivsize(keys->Ke));
	if (ret < 0)
		goto error;

	ret = crypto_shash_update_sg(desc, sg);
	if (ret < 0)
		goto error;

	ret = crypto_shash_final(desc, cksum);
	if (ret < 0)
		goto error;

	/* Append the checksum into the buffer. */
	ret = skb_store_bits(skb, cksum_offset, cksum, gk5e->cksumlength);
	if (ret < 0)
		goto error;

	ret = secure_len;

error:
	kfree_sensitive(buffer);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Apply decryption and checksumming functions to part of an skbuff.  The
 * offset and length are updated to reflect the actual content of the encrypted
 * region.
 */
static int rfc8009_decrypt_skb(struct rxrpc_call *call,
			       const struct rxgk_krb5_enctype *gk5e,
			       struct rxgk_enc_keys *keys,
			       struct sk_buff *skb,
			       unsigned int *_offset, unsigned int *_len,
			       u32 *_abort_code)
{
	struct skcipher_request	*req;
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct scatterlist sg[16];
	struct shash_desc *desc;
	unsigned int offset = *_offset, len = *_len;
	size_t bsize;
	void *buffer = NULL;
	int ret;
	u8 *cksum, *cksum2, *iv;

	_enter("");

	if (len < gk5e->conflen + gk5e->cksumlength) {
		trace_rxrpc_rx_eproto(call, sp->hdr.serial, "rxgk_len");
		*_abort_code = RXGK_SEALED_INCON;
		return -EPROTO;
	}

	bsize = rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki) * 2 +
		rxgk_sync_skcipher_size(keys->Ke) +
		rxgk_sync_skcipher_ivsize(keys->Ke);
	buffer = kzalloc(bsize, GFP_NOFS);
	if (!buffer)
		return -ENOMEM;

	cksum = buffer +
		rxgk_shash_size(keys->Ki);
	cksum2 = buffer +
		rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki);
	req = buffer +
		rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki) * 2;
	iv = buffer +
		rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki) * 2 +
		rxgk_sync_skcipher_size(keys->Ke);

	/* Set up an s-g list to cover the encrypted region. */
	sg_init_table(sg, ARRAY_SIZE(sg));
	ret = skb_to_sgvec(skb, sg, offset, len - gk5e->cksumlength);
	if (unlikely(ret < 0))
		goto error;

	/* Calculate the checksum using key Ki */
	desc = buffer;
	desc->tfm = keys->Ki;
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	ret = crypto_shash_update(desc, iv, crypto_sync_skcipher_ivsize(keys->Ke));
	if (ret < 0)
		goto error;

	ret = crypto_shash_update_sg(desc, sg);
	if (ret < 0)
		goto error;

	ret = crypto_shash_final(desc, cksum);
	if (ret < 0)
		goto error;

	/* Get the checksum from the buffer. */
	ret = skb_copy_bits(skb, offset + len - gk5e->cksumlength, cksum2, gk5e->cksumlength);
	if (ret < 0)
		goto error;

	if (memcmp(cksum, cksum2, gk5e->cksumlength) != 0) {
		trace_rxrpc_rx_eproto(call, sp->hdr.serial, "rxgk_cksum");
		*_abort_code = RXGK_SEALED_INCON;
		ret = -EPROTO;
		goto error;
	}

	/* Decrypt the secure region with key Ke. */
	skcipher_request_set_sync_tfm(req, keys->Ke);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, sg, sg, len - gk5e->cksumlength, iv);
	ret = crypto_skcipher_decrypt(req);

	*_offset += gk5e->conflen;
	*_len -= gk5e->conflen + gk5e->cksumlength;
	ret = 0;

error:
	kfree_sensitive(buffer);
	_leave(" = %d", ret);
	return ret;
}

static const struct rxgk_crypto_scheme rfc8009_crypto_scheme = {
	.calc_PRF	= rfc8009_calc_PRF,
	.calc_Kc	= rfc8009_calc_Ki,
	.calc_Ke	= rfc8009_calc_Ke,
	.calc_Ki	= rfc8009_calc_Ki,
	.encrypt_skb	= rfc8009_encrypt_skb,
	.decrypt_skb	= rfc8009_decrypt_skb,
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
