/* rfc3961 Encryption and Checksum Specifications for Kerberos 5
 *
 * Parts borrowed from net/sunrpc/auth_gss/.
 */
/*
 * COPYRIGHT (c) 2008
 * The Regents of the University of Michigan
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * RxGK bits:
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

static int rfc3961_do_encrypt(struct crypto_sync_skcipher *tfm, void *iv,
			      const struct rxgk_buffer *in, struct rxgk_buffer *out)
{
	struct scatterlist sg[1];
	u8 local_iv[GSS_KRB5_MAX_BLOCKSIZE] = {0};
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);
	int ret;

	_enter("");

	if (WARN_ON(in->len != out->len))
		return -EINVAL;
	if (out->len % crypto_sync_skcipher_blocksize(tfm) != 0)
		return -EINVAL;

	if (crypto_sync_skcipher_ivsize(tfm) > GSS_KRB5_MAX_BLOCKSIZE) {
		_leave(" = -EINVAL [tfm iv too large %d]",
		       crypto_sync_skcipher_ivsize(tfm));
		return -EINVAL;
	}

	if (iv)
		memcpy(local_iv, iv, crypto_sync_skcipher_ivsize(tfm));

	memcpy(out->data, in->data, out->len);
	sg_init_one(sg, out->data, out->len);

	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, sg, sg, out->len, local_iv);

	ret = crypto_skcipher_encrypt(req);
	skcipher_request_zero(req);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Calculate an unkeyed basic hash.
 */
static int rfc3961_calc_H(const struct rxgk_krb5_enctype *gk5e,
			  const struct rxgk_buffer *data,
			  struct rxgk_buffer *digest,
			  gfp_t gfp)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t desc_size;
	int ret = -ENOMEM;

	_enter("");

	tfm = crypto_alloc_shash(gk5e->hash_name, 0, 0);
	if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? -ENOPKG : PTR_ERR(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);

	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc)
		goto error_tfm;

	digest->len = crypto_shash_digestsize(tfm);
	digest->data = kzalloc(digest->len, gfp);
	if (!digest->data)
		goto error_desc;

	desc->tfm = tfm;
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error_digest;

	ret = crypto_shash_finup(desc, data->data, data->len, digest->data);
	if (ret < 0)
		goto error_digest;

	goto error_desc;

error_digest:
	kfree_sensitive(digest->data);
error_desc:
	kfree_sensitive(desc);
error_tfm:
	crypto_free_shash(tfm);
	_leave(" = %d", ret);
	return ret;
}

/*
 * This is the n-fold function as described in rfc3961, sec 5.1
 * Taken from MIT Kerberos and modified.
 */
static void rfc3961_nfold(const struct rxgk_buffer *source, struct rxgk_buffer *result)
{
	const u8 *in = source->data;
	u8 *out = result->data;
	unsigned long ulcm;
	unsigned int inbits, outbits;
	int byte, i, msbit;

	_enter("");

	/* the code below is more readable if I make these bytes instead of bits */
	inbits = source->len;
	outbits = result->len;

	/* first compute lcm(n,k) */
	ulcm = lcm(inbits, outbits);

	/* now do the real work */
	memset(out, 0, outbits);
	byte = 0;

	/* this will end up cycling through k lcm(k,n)/k times, which
	 * is correct */
	for (i = ulcm-1; i >= 0; i--) {
		/* compute the msbit in k which gets added into this byte */
		msbit = (
			/* first, start with the msbit in the first,
			 * unrotated byte */
			((inbits << 3) - 1) +
			/* then, for each byte, shift to the right
			 * for each repetition */
			(((inbits << 3) + 13) * (i/inbits)) +
			/* last, pick out the correct byte within
			 * that shifted repetition */
			((inbits - (i % inbits)) << 3)
			 ) % (inbits << 3);

		/* pull out the byte value itself */
		byte += (((in[((inbits - 1) - (msbit >> 3)) % inbits] << 8) |
			  (in[((inbits)     - (msbit >> 3)) % inbits]))
			 >> ((msbit & 7) + 1)) & 0xff;

		/* do the addition */
		byte += out[i % outbits];
		out[i % outbits] = byte & 0xff;

		/* keep around the carry bit, if any */
		byte >>= 8;
	}

	/* if there's a carry bit left over, add it back in */
	if (byte) {
		for (i = outbits - 1; i >= 0; i--) {
			/* do the addition */
			byte += out[i];
			out[i] = byte & 0xff;

			/* keep around the carry bit, if any */
			byte >>= 8;
		}
	}

	_leave("");
}

/*
 * Calculate a derived key, DK(Base Key, Well-Known Constant)
 *
 * DK(Key, Constant) = random-to-key(DR(Key, Constant))
 * DR(Key, Constant) = k-truncate(E(Key, Constant, initial-cipher-state))
 * K1 = E(Key, n-fold(Constant), initial-cipher-state)
 * K2 = E(Key, K1, initial-cipher-state)
 * K3 = E(Key, K2, initial-cipher-state)
 * K4 = ...
 * DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)
 * [rfc3961 sec 5.1]
 */
static int rfc3961_calc_DK(const struct rxgk_krb5_enctype *gk5e,
			   const struct rxgk_buffer *inkey,
			   const struct rxgk_buffer *in_constant,
			   struct rxgk_buffer *result,
			   gfp_t gfp)
{
	unsigned int blocksize, keybytes, keylength, n;
	struct rxgk_buffer inblock, outblock, rawkey;
	struct crypto_sync_skcipher *cipher;
	int ret = -EINVAL;

	_enter("");

	blocksize = gk5e->blocksize;
	keybytes = gk5e->keybytes;
	keylength = gk5e->keylength;

	if (inkey->len != keylength || result->len != keylength) {
		_leave(" = -EINVAL [%u,%u != %u]",
		       inkey->len, result->len, keylength);
		return -EINVAL;
	}

	cipher = crypto_alloc_sync_skcipher(gk5e->encrypt_name, 0, 0);
	if (IS_ERR(cipher)) {
		ret = (PTR_ERR(cipher) == -ENOENT) ? -ENOPKG : PTR_ERR(cipher);
		_debug("alloc %s", gk5e->encrypt_name);
		goto err_return;
	}
	ret = crypto_sync_skcipher_setkey(cipher, inkey->data, inkey->len);
	if (ret < 0) {
		_debug("setkey %d %u", ret, inkey->len);
		goto err_free_cipher;
	}

	ret = -ENOMEM;
	inblock.data = kzalloc(blocksize * 2 + keybytes, gfp);
	if (!inblock.data)
		goto err_free_cipher;

	inblock.len	= blocksize;
	outblock.data	= inblock.data + blocksize;
	outblock.len	= blocksize;
	rawkey.data	= outblock.data + blocksize;
	rawkey.len	= keybytes;

	/* initialize the input block */

	if (in_constant->len == inblock.len)
		memcpy(inblock.data, in_constant->data, inblock.len);
	else
		rfc3961_nfold(in_constant, &inblock);

	/* loop encrypting the blocks until enough key bytes are generated */
	n = 0;
	while (n < rawkey.len) {
		rfc3961_do_encrypt(cipher, NULL, &inblock, &outblock);

		if (keybytes - n <= outblock.len) {
			memcpy(rawkey.data + n, outblock.data, keybytes - n);
			break;
		}

		memcpy(rawkey.data + n, outblock.data, outblock.len);
		memcpy(inblock.data, outblock.data, outblock.len);
		n += outblock.len;
	}

	/* postprocess the key */
	ret = gk5e->random_to_key(gk5e, &rawkey, result);

	kfree_sensitive(inblock.data);
err_free_cipher:
	crypto_free_sync_skcipher(cipher);
err_return:
	_leave(" = %d", ret);
	return ret;
}

/*
 * Calculate single encryption, E()
 *
 *	E(Key, octets)
 */
static int rfc3961_calc_E(const struct rxgk_krb5_enctype *gk5e,
			  const struct rxgk_buffer *key,
			  const struct rxgk_buffer *in_data,
			  struct rxgk_buffer *result,
			  gfp_t gfp)
{
	struct crypto_sync_skcipher *cipher;
	int ret;

	_enter("");

	cipher = crypto_alloc_sync_skcipher(gk5e->encrypt_name, 0, 0);
	if (IS_ERR(cipher)) {
		ret = (PTR_ERR(cipher) == -ENOENT) ? -ENOPKG : PTR_ERR(cipher);
		goto err;
	}

	ret = crypto_sync_skcipher_setkey(cipher, key->data, key->len);
	if (ret < 0)
		goto err_free;

	ret = rfc3961_do_encrypt(cipher, NULL, in_data, result);

err_free:
	crypto_free_sync_skcipher(cipher);
err:
	_leave(" = %d", ret);
	return ret;
}

/*
 * Calculate the pseudo-random function, PRF().
 *
 *      tmp1 = H(octet-string)
 *      tmp2 = truncate tmp1 to multiple of m
 *      PRF = E(DK(protocol-key, prfconstant), tmp2, initial-cipher-state)
 *
 *      The "prfconstant" used in the PRF operation is the three-octet string
 *      "prf".
 *      [rfc3961 sec 5.3]
 */
static int rfc3961_calc_PRF(const struct rxgk_krb5_enctype *gk5e,
			    const struct rxgk_buffer *protocol_key,
			    const struct rxgk_buffer *octet_string,
			    struct rxgk_buffer *result,
			    gfp_t gfp)
{
	static const struct rxgk_buffer prfconstant = { 3, "prf" };
	struct rxgk_buffer derived_key;
	struct rxgk_buffer tmp1, tmp2;
	unsigned int m = gk5e->blocksize;
	void *buffer;
	int ret;

	_enter("");

	if (result->len != gk5e->prf_len) {
		_leave(" = -EINVAL [result len %u!=%u]",
		       result->len, gk5e->prf_len);
		return -EINVAL;
	}

	tmp1.len = gk5e->hashbytes;
	derived_key.len = gk5e->keybytes;
	buffer = kzalloc(round16(tmp1.len) + round16(derived_key.len), gfp);
	if (!buffer)
		return -ENOMEM;

	tmp1.data = buffer;
	derived_key.data = buffer + round16(tmp1.len);

	ret = rfc3961_calc_H(gk5e, octet_string, &tmp1, gfp);
	if (ret < 0)
		goto err;

	tmp2.len = tmp1.len & ~(m - 1);
	tmp2.data = tmp1.data;

	ret = rfc3961_calc_DK(gk5e, protocol_key, &prfconstant, &derived_key, gfp);
	if (ret < 0)
		goto err;

	ret = rfc3961_calc_E(gk5e, &derived_key, &tmp2, result, gfp);

err:
	kfree_sensitive(buffer);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Apply encryption and checksumming functions to part of an skbuff.
 */
int rfc3961_encrypt_skb(const struct rxgk_krb5_enctype *gk5e,
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
	if (gk5e->pad) {
		secure_len = round_up(base_len, gk5e->blocksize);
		pad_len    = secure_len - base_len;
	} else {
		secure_len = base_len;
		pad_len    = 0;
	}
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

	/* Calculate the checksum using key Ki */
	cksum = buffer + rxgk_shash_size(keys->Ki);

	desc = buffer;
	desc->tfm = keys->Ki;
	ret = crypto_shash_init(desc);
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
int rfc3961_decrypt_skb(struct rxrpc_call *call,
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

	/* Set up an s-g list to cover the encrypted region. */
	sg_init_table(sg, ARRAY_SIZE(sg));
	ret = skb_to_sgvec(skb, sg, offset, len - gk5e->cksumlength);
	if (unlikely(ret < 0))
		goto error;

	/* Decrypt the secure region with key Ke. */
	req = buffer +
		rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki) * 2;
	iv = buffer +
		rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki) * 2 +
		rxgk_sync_skcipher_size(keys->Ke);

	skcipher_request_set_sync_tfm(req, keys->Ke);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, sg, sg, len - gk5e->cksumlength, iv);
	ret = crypto_skcipher_decrypt(req);
	if (ret < 0)
		goto error;

	/* Calculate the checksum using key Ki */
	cksum = buffer +
		rxgk_shash_size(keys->Ki);
	cksum2 = buffer +
		rxgk_shash_size(keys->Ki) +
		rxgk_digest_size(keys->Ki);

	desc = buffer;
	desc->tfm = keys->Ki;
	ret = crypto_shash_init(desc);
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

	*_offset += gk5e->conflen;
	*_len -= gk5e->conflen + gk5e->cksumlength;
	ret = 0;

error:
	kfree_sensitive(buffer);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Generate a checksum over some metadata and part of an skbuff and insert the
 * MIC into the skbuff immediately prior to the data.
 */
int rfc3961_get_mic_skb(const struct rxgk_krb5_enctype *gk5e,
			struct crypto_shash *shash,
			const struct rxgk_buffer *metadata,
			struct sk_buff *skb,
			u16 data_offset, u16 data_len)
{
	struct scatterlist sg[16];
	struct shash_desc *desc;
	size_t bsize;
	void *buffer, *digest;
	int ret = -ENOMEM;

	_enter("");

	if (WARN_ON(data_offset < gk5e->cksumlength))
		return -EINVAL;

	bsize = rxgk_shash_size(shash) +
		rxgk_digest_size(shash);
	buffer = kzalloc(bsize, GFP_NOFS);
	if (!buffer)
		return -ENOMEM;

	/* Calculate the MIC with key Kc and store it into the skb */
	desc = buffer;
	desc->tfm = shash;
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	if (metadata) {
		ret = crypto_shash_update(desc, metadata->data, metadata->len);
		if (ret < 0)
			goto error;
	}

	sg_init_table(sg, ARRAY_SIZE(sg));
	ret = skb_to_sgvec(skb, sg, gk5e->cksumlength, data_len);
	if (unlikely(ret < 0))
		goto error;

	ret = crypto_shash_update_sg(desc, sg);
	if (ret < 0)
		goto error;

	digest = buffer + rxgk_shash_size(shash);
	ret = crypto_shash_final(desc, digest);
	if (ret < 0)
		goto error;

	ret = skb_store_bits(skb, data_offset - gk5e->cksumlength,
			     digest, gk5e->cksumlength);
	if (ret < 0)
		goto error;

	ret = data_len;

error:
	kfree_sensitive(buffer);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Check the MIC on a region of an skbuff.  The offset and length are updated
 * to reflect the actual content of the secure region.
 */
int rfc3961_verify_mic_skb(struct rxrpc_call *call,
			   const struct rxgk_krb5_enctype *gk5e,
			   struct crypto_shash *shash,
			   const struct rxgk_buffer *metadata,
			   struct sk_buff *skb,
			   unsigned int *_offset, unsigned int *_len,
			   u32 *_abort_code)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct scatterlist sg[16];
	struct shash_desc *desc;
	unsigned int offset = *_offset, len = *_len;
	size_t bsize;
	void *buffer = NULL;
	int ret;
	u8 *cksum, *cksum2;

	_enter("");

	if (len < gk5e->cksumlength) {
		trace_rxrpc_rx_eproto(call, sp->hdr.serial, "rxgk_1_len");
		*_abort_code = RXGK_SEALED_INCON;
		return -EPROTO;
	}

	bsize = rxgk_shash_size(shash) +
		rxgk_digest_size(shash) * 2;
	buffer = kzalloc(bsize, GFP_NOFS);
	if (!buffer)
		return -ENOMEM;

	cksum = buffer +
		rxgk_shash_size(shash);
	cksum2 = buffer +
		rxgk_shash_size(shash) +
		rxgk_digest_size(shash);

	/* Calculate the MIC */
	desc = buffer;
	desc->tfm = shash;
	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	if (metadata) {
		ret = crypto_shash_update(desc, metadata->data, metadata->len);
		if (ret < 0)
			goto error;
	}

	sg_init_table(sg, ARRAY_SIZE(sg));
	ret = skb_to_sgvec(skb, sg, offset + gk5e->cksumlength,
			   len - gk5e->cksumlength);
	if (unlikely(ret < 0))
		goto error;

	crypto_shash_update_sg(desc, sg);
	crypto_shash_final(desc, cksum);

	ret = skb_copy_bits(skb, offset, cksum2, gk5e->cksumlength);
	if (ret < 0)
		goto error;

	if (memcmp(cksum, cksum2, gk5e->cksumlength) != 0) {
		trace_rxrpc_rx_eproto(call, sp->hdr.serial, "rxgk_1_mic");
		*_abort_code = RXGK_SEALED_INCON;
		ret = -EPROTO;
		goto error;
	}

	*_offset += gk5e->cksumlength;
	*_len -= gk5e->cksumlength;
	ret = 0;

error:
	kfree_sensitive(buffer);
	_leave(" = %d", ret);
	return ret;
}

const struct rxgk_crypto_scheme rfc3961_crypto_scheme = {
	.calc_PRF	= rfc3961_calc_PRF,
	.calc_Kc	= rfc3961_calc_DK,
	.calc_Ke	= rfc3961_calc_DK,
	.calc_Ki	= rfc3961_calc_DK,
	.encrypt_skb	= rfc3961_encrypt_skb,
	.decrypt_skb	= rfc3961_decrypt_skb,
	.get_mic_skb	= rfc3961_get_mic_skb,
	.verify_mic_skb	= rfc3961_verify_mic_skb,
};

/**
 * crypto_krb5_how_much_buffer - Work out how much buffer is required for an amount of data
 * @krb5: The encoding to use.
 * @mode: The mode in which to operated (checksum/encrypt)
 * @pad: True if the data should be padded anyway
 * @data_size: How much data we want to allow for
 * @_offset: Where to place the offset into the buffer
 *
 * Calculate how much buffer space is required to wrap a given amount of data.
 * This allows for a confounder, padding and checksum as appropriate.  The
 * amount of buffer required is returned and the offset into the buffer at
 * which the data will start is placed in *_offset.
 */
size_t rxgk_krb5_how_much_buffer(const struct rxgk_krb5_enctype *gk5e,
				 enum krb5_crypto_mode mode, bool pad,
				 size_t data_size, size_t *_offset)
{
	switch (mode) {
	case KRB5_CHECKSUM_MODE:
		*_offset = 0;
		return gk5e->cksumlength + data_size;

	case KRB5_ENCRYPT_MODE:
		data_size += gk5e->conflen;
		if (pad || gk5e->pad)
			data_size = round_up(data_size, gk5e->blocksize);
		*_offset = gk5e->conflen;
		return gk5e->cksumlength + data_size;

	default:
		WARN_ON(1);
		*_offset = 0;
		return 0;
	}
}

/**
 * crypto_krb5_how_much_data - Work out how much data can fit in an amount of buffer
 * @krb5: The encoding to use.
 * @mode: The mode in which to operated (checksum/encrypt)
 * @pad: True if the data should be padded anyway
 * @_buffer_size: How much buffer we want to allow for (may be reduced)
 * @_offset: Where to place the offset into the buffer
 *
 * Calculate how much data can be fitted into given amount of buffer.  This
 * allows for a confounder, padding and checksum as appropriate.  The amount of
 * data that will fit is returned, the amount of buffer required is shrunk to
 * allow for alignment and the offset into the buffer at which the data will
 * start is placed in *_offset.
 */
size_t rxgk_krb5_how_much_data(const struct rxgk_krb5_enctype *gk5e,
			       enum krb5_crypto_mode mode, bool pad,
			       size_t *_buffer_size, size_t *_offset)
{
	size_t buffer_size = *_buffer_size, data_size, aligned_size;

	switch (mode) {
	case KRB5_CHECKSUM_MODE:
		if (WARN_ON(buffer_size < gk5e->cksumlength + 1))
			goto bad;
		*_offset = 0;
		return buffer_size - gk5e->cksumlength;

	case KRB5_ENCRYPT_MODE:
		if (WARN_ON(buffer_size < gk5e->conflen + 1 + gk5e->cksumlength))
			goto bad;
		data_size = buffer_size - gk5e->cksumlength;
		if (pad || gk5e->pad) {
			aligned_size = round_down(data_size, gk5e->blocksize);
			*_buffer_size -= data_size - aligned_size;
			data_size = aligned_size;
		}

		*_offset = gk5e->conflen;
		return data_size - gk5e->conflen;

	default:
		WARN_ON(1);
		goto bad;
	}

bad:
	*_offset = 0;
	return 0;
}
