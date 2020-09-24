// SPDX-License-Identifier: GPL-2.0-or-later
/* RxGK transport key derivation.
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

static const struct rxgk_krb5_enctype *const rxgk_supported_krb5_enctypes[] = {
	&rxgk_aes128_cts_hmac_sha1_96,
	&rxgk_aes256_cts_hmac_sha1_96,
	&rxgk_aes128_cts_hmac_sha256_128,
	&rxgk_aes256_cts_hmac_sha384_192,
};

/*
 * Find the handler for an encryption type
 */
const struct rxgk_krb5_enctype *rxgk_find_enctype(u32 enctype)
{
	const struct rxgk_krb5_enctype *gk5e;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(rxgk_supported_krb5_enctypes); i++) {
		gk5e = rxgk_supported_krb5_enctypes[i];
		if (gk5e->etype == enctype) {
			_leave(" = [%s]", gk5e->name);
			return gk5e;
		}
	}

	_leave(" = NULL");
	return NULL;
}

void rxgk_free_enc_keys(struct rxgk_enc_keys *e)
{
	if (e->Ke)
		crypto_free_sync_skcipher(e->Ke);
	if (e->Ki)
		crypto_free_shash(e->Ki);
	e->Ke = NULL;
	e->Ki = NULL;
}

static void rxgk_free(struct rxgk_context *gk)
{
	if (gk->tx_Kc)
		crypto_free_shash(gk->tx_Kc);
	if (gk->rx_Kc)
		crypto_free_shash(gk->rx_Kc);
	rxgk_free_enc_keys(&gk->tx_enc);
	rxgk_free_enc_keys(&gk->rx_enc);
	rxgk_free_enc_keys(&gk->resp_enc);
	kfree(gk);
}

void rxgk_put(struct rxgk_context *gk)
{
	if (gk && refcount_dec_and_test(&gk->usage))
		rxgk_free(gk);
}

int crypto_shash_update_sg(struct shash_desc *desc, struct scatterlist *sg)
{
	for (;; sg++) {
		struct page *page = sg_page(sg);
		void *p = kmap_atomic(page);
		int ret;

		ret = crypto_shash_update(desc, p + sg->offset, sg->length);
		kunmap_atomic(p);
		if (ret < 0)
			return ret;
		if (sg_is_last(sg))
			break;
	}

	return 0;
}

/*
 * Calculate the kerberos pseudo-random function, PRF+()
 *
 *      PRF+(K, L, S) = truncate(L, T1 || T2 || .. || Tn)
 *      Tn = PRF(K, n || S)
 *      [rfc4402 sec 2]
 */
static int rxgk_calc_PRFplus(const struct rxgk_krb5_enctype *gk5e,
			     const struct rxgk_buffer *K,
			     unsigned int L,
			     const struct rxgk_buffer *S,
			     struct rxgk_buffer *result,
			     gfp_t gfp)
{
	struct rxgk_buffer T_series, Tn, n_S;
	void *buffer;
	int ret, n = 1;

	_enter("");

	Tn.len = gk5e->prf_len;
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
		ret = gk5e->scheme->calc_PRF(gk5e, K, &n_S, &Tn, gfp);
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
	_leave(" = %d", ret);
	return ret;
}

/*
 * Transport key derivation function.
 *
 *      TK = random-to-key(PRF+(K0, L,
 *                         epoch || cid || start_time || key_number))
 *      [tools.ietf.org/html/draft-wilkinson-afs3-rxgk-11 sec 8.3]
 */
static int rxgk_derive_transport_key(struct rxrpc_connection *conn,
				     struct rxgk_context *gk,
				     const struct rxgk_key *rxgk,
				     struct rxgk_buffer *TK,
				     gfp_t gfp)
{
	const struct rxgk_krb5_enctype *gk5e = gk->gk5e;
	struct rxgk_buffer conn_info;
	unsigned int L = gk5e->keybytes;
	__be32 *info;
	u8 *buffer;
	int ret;

	_enter("");

	conn_info.len = sizeof(__be32) * 5;

	buffer = kzalloc(round16(conn_info.len), gfp);
	if (!buffer)
		return -ENOMEM;

	conn_info.data = buffer;

	info = (__be32 *)conn_info.data;
	info[0] = htonl(conn->proto.epoch);
	info[1] = htonl(conn->proto.cid);
	info[2] = htonl(conn->rxgk.start_time >> 32);
	info[3] = htonl(conn->rxgk.start_time >>  0);
	info[4] = htonl(gk->key_number);

	ret = rxgk_calc_PRFplus(gk5e, &rxgk->key, L, &conn_info, TK, gfp);
	kfree_sensitive(buffer);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Constants used to derive the keys and hmacs actually used for doing stuff.
 */
#define DERIVATION_CONSTANT(NAME, C, TAG)				\
	static const u8 NAME##_buf[5] = {				\
		(C >> 24) & 0xff, (C >> 16) & 0xff, (C >> 8) & 0xff, (C >> 0) & 0xff, \
		TAG };							\
	static const struct rxgk_buffer NAME = {			\
		.len = 5, .data = (u8 *)NAME##_buf };

/*
 * Kc = DK(base-key, usage | 0x99);
 * Ke = DK(base-key, usage | 0xAA);
 * Ki = DK(base-key, usage | 0x55);
 */
#define RXGK_CLIENT_ENC_PACKET		1026U // 0x402
#define RXGK_CLIENT_MIC_PACKET          1027U // 0x403
#define RXGK_SERVER_ENC_PACKET          1028U // 0x404
#define RXGK_SERVER_MIC_PACKET          1029U // 0x405
#define RXGK_CLIENT_ENC_RESPONSE        1030U // 0x406
#define RXGK_SERVER_ENC_TOKEN           1036U // 0x40c

DERIVATION_CONSTANT(rxgk_const_client_Kc, RXGK_CLIENT_MIC_PACKET, 0x99);
DERIVATION_CONSTANT(rxgk_const_client_Ke, RXGK_CLIENT_ENC_PACKET, 0xaa);
DERIVATION_CONSTANT(rxgk_const_client_Ki, RXGK_CLIENT_ENC_PACKET, 0x55);
DERIVATION_CONSTANT(rxgk_const_server_Kc, RXGK_SERVER_MIC_PACKET, 0x99);
DERIVATION_CONSTANT(rxgk_const_server_Ke, RXGK_SERVER_ENC_PACKET, 0xaa);
DERIVATION_CONSTANT(rxgk_const_server_Ki, RXGK_SERVER_ENC_PACKET, 0x55);
DERIVATION_CONSTANT(rxgk_const_resp_Ke,   RXGK_CLIENT_ENC_RESPONSE, 0xaa);
DERIVATION_CONSTANT(rxgk_const_resp_Ki,   RXGK_CLIENT_ENC_RESPONSE, 0x55);
DERIVATION_CONSTANT(rxgk_const_token_Ke,  RXGK_SERVER_ENC_TOKEN,  0xaa);
DERIVATION_CONSTANT(rxgk_const_token_Ki,  RXGK_SERVER_ENC_TOKEN,  0x55);

/*
 * Set up a hash for Kc.
 */
static int rxgk_get_Kc(const struct rxgk_krb5_enctype *gk5e,
		       const struct rxgk_buffer *TK,
		       const struct rxgk_buffer *usage_constant,
		       struct rxgk_buffer *key,
		       struct crypto_shash **_shash,
		       gfp_t gfp)
{
	struct crypto_shash *shash;
	int ret;

	key->len = gk5e->Kc_len;
	ret = gk5e->scheme->calc_Kc(gk5e, TK, usage_constant, key, gfp);
	if (ret < 0)
		return ret;

	shash = crypto_alloc_shash(gk5e->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
	*_shash = shash;
	return crypto_shash_setkey(shash, key->data, key->len);
}

/*
 * Set up a cipher for Ke.
 */
static int rxgk_get_Ke(const struct rxgk_krb5_enctype *gk5e,
		       const struct rxgk_buffer *TK,
		       const struct rxgk_buffer *usage_constant,
		       struct rxgk_buffer *key,
		       struct crypto_sync_skcipher **_ci,
		       gfp_t gfp)
{
	struct crypto_sync_skcipher *ci;
	int ret;

	key->len = gk5e->Ke_len;
	ret = gk5e->scheme->calc_Ke(gk5e, TK, usage_constant, key, gfp);
	if (ret < 0)
		return ret;

	ci = crypto_alloc_sync_skcipher(gk5e->encrypt_name, 0, 0);
	if (IS_ERR(ci))
		return (PTR_ERR(ci) == -ENOENT) ? -ENOPKG : PTR_ERR(ci);
	*_ci = ci;
	return crypto_sync_skcipher_setkey(ci, key->data, key->len);
}

/*
 * Set up a hash for Ki.
 */
static int rxgk_get_Ki(const struct rxgk_krb5_enctype *gk5e,
		       const struct rxgk_buffer *TK,
		       const struct rxgk_buffer *usage_constant,
		       struct rxgk_buffer *key,
		       struct crypto_shash **_shash,
		       gfp_t gfp)
{
	struct crypto_shash *shash;
	int ret;

	key->len = gk5e->Ki_len;
	ret = gk5e->scheme->calc_Kc(gk5e, TK, usage_constant, key, gfp);
	if (ret < 0)
		return ret;

	shash = crypto_alloc_shash(gk5e->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
	*_shash = shash;
	return crypto_shash_setkey(shash, key->data, key->len);
}

/*
 * Set up the ciphers for the usage keys.
 */
static int rxgk_set_up_ciphers(struct rxrpc_connection *conn,
			       struct rxgk_context *gk,
			       const struct rxgk_key *rxgk,
			       gfp_t gfp)
{
	const struct rxgk_krb5_enctype *gk5e = gk->gk5e;
	struct rxgk_buffer TK, key;
	bool service = rxrpc_conn_is_service(conn);
	int ret;
	u8 *buffer;

	buffer = kzalloc(gk5e->keybytes * 2, gfp);
	if (!buffer)
		return -ENOMEM;

	TK.len = gk5e->keybytes;
	TK.data = buffer;
	key.len = gk5e->keybytes;
	key.data = buffer + gk5e->keybytes;

	ret = rxgk_derive_transport_key(conn, gk, rxgk, &TK, gfp);
	if (ret < 0)
		goto out;

#define DERIVE_Kc(KEY, CONSTANT, KC)				\
	ret = rxgk_get_Kc(gk5e, KEY, &CONSTANT, &key, KC, gfp); \
	if (ret < 0) goto out;
#define DERIVE_Ke(KEY, CONSTANT, KE)				\
	ret = rxgk_get_Ke(gk5e, KEY, &CONSTANT, &key, KE, gfp); \
	if (ret < 0) goto out;
#define DERIVE_Ki(KEY, CONSTANT, KI)				\
	ret = rxgk_get_Ki(gk5e, KEY, &CONSTANT, &key, KI, gfp); \
	if (ret < 0) goto out;

	DERIVE_Ke(&TK, rxgk_const_resp_Ke, &gk->resp_enc.Ke);
	DERIVE_Ki(&TK, rxgk_const_resp_Ki, &gk->resp_enc.Ki);

	if (crypto_sync_skcipher_blocksize(gk->resp_enc.Ke) != gk5e->blocksize ||
	    crypto_shash_digestsize(gk->resp_enc.Ki) < gk5e->cksumlength) {
		pr_notice("algo inconsistent with gss table %u!=%u or %u!=%u\n",
			  crypto_sync_skcipher_blocksize(gk->resp_enc.Ke), gk5e->blocksize,
			  crypto_shash_digestsize(gk->resp_enc.Ki), gk5e->cksumlength);
		return -EINVAL;
	}

	if (service) {
		switch (conn->params.security_level) {
		case RXRPC_SECURITY_AUTH:
			DERIVE_Kc(&TK, rxgk_const_client_Kc, &gk->rx_Kc);
			DERIVE_Kc(&TK, rxgk_const_server_Kc, &gk->tx_Kc);
			break;
		case RXRPC_SECURITY_ENCRYPT:
			DERIVE_Ke(&TK, rxgk_const_client_Ke, &gk->rx_enc.Ke);
			DERIVE_Ki(&TK, rxgk_const_client_Ki, &gk->rx_enc.Ki);
			DERIVE_Ke(&TK, rxgk_const_server_Ke, &gk->tx_enc.Ke);
			DERIVE_Ki(&TK, rxgk_const_server_Ki, &gk->tx_enc.Ki);
			break;
		}
	} else {
		switch (conn->params.security_level) {
		case RXRPC_SECURITY_AUTH:
			DERIVE_Kc(&TK, rxgk_const_client_Kc, &gk->tx_Kc);
			DERIVE_Kc(&TK, rxgk_const_server_Kc, &gk->rx_Kc);
			break;
		case RXRPC_SECURITY_ENCRYPT:
			DERIVE_Ke(&TK, rxgk_const_client_Ke, &gk->tx_enc.Ke);
			DERIVE_Ki(&TK, rxgk_const_client_Ki, &gk->tx_enc.Ki);
			DERIVE_Ke(&TK, rxgk_const_server_Ke, &gk->rx_enc.Ke);
			DERIVE_Ki(&TK, rxgk_const_server_Ki, &gk->rx_enc.Ki);
			break;
		}
	}

	ret = 0;
out:
	kfree_sensitive(buffer);
	return ret;
}

/*
 * Derive a transport key for a connection and then derive a bunch of usage
 * keys from it and set up ciphers using them.
 */
struct rxgk_context *rxgk_generate_transport_key(struct rxrpc_connection *conn,
						 const struct rxgk_key *key,
						 unsigned int key_number,
						 gfp_t gfp)
{
	struct rxgk_context *gk;
	unsigned long lifetime;
	int ret;

	_enter("");

	gk = kzalloc(sizeof(struct rxgk_context), GFP_KERNEL);
	if (!gk)
		return ERR_PTR(-ENOMEM);
	refcount_set(&gk->usage, 1);
	gk->key		= key;
	gk->key_number	= key_number;

	gk->gk5e = rxgk_find_enctype(key->enctype);
	if (!gk->gk5e) {
		ret = -ENOPKG;
		goto err_tk;
	}

	ret = rxgk_set_up_ciphers(conn, gk, key, gfp);
	if (ret)
		goto err_tk;

	/* Set the remaining number of bytes encrypted with this key that may
	 * be transmitted before rekeying.  Note that the spec has been
	 * interpreted differently on this point... */
	switch (key->bytelife) {
	case 0:
	case 63:
		gk->bytes_remaining = LLONG_MAX;
		break;
	case 1 ... 62:
		gk->bytes_remaining = 1LL << key->bytelife;
		break;
	default:
		gk->bytes_remaining = key->bytelife;
		break;
	}

	/* Set the time after which rekeying must occur */
	if (key->lifetime) {
		lifetime = min_t(u64, key->lifetime, INT_MAX / HZ);
		lifetime *= HZ;
	} else {
		lifetime = MAX_JIFFY_OFFSET;
	}
	gk->expiry = jiffies + lifetime;
	return gk;

err_tk:
	rxgk_put(gk);
	_leave(" = %d", ret);
	return ERR_PTR(ret);
}

/*
 * Use the server secret key to set up the ciphers that will be used to extract
 * the token from a response packet.
 */
int rxgk_set_up_token_cipher(const struct rxgk_buffer *server_key,
			     struct rxgk_enc_keys *token_key,
			     unsigned int enctype,
			     const struct rxgk_krb5_enctype **_gk5e,
			     gfp_t gfp)
{
	const struct rxgk_krb5_enctype *gk5e;
	struct rxgk_buffer key;
	int ret;

	ret = -ENOPKG;
	gk5e = rxgk_find_enctype(enctype);
	if (!gk5e)
		goto out_buf;

	*_gk5e = gk5e;

	key.len = gk5e->keybytes;
	key.data = kzalloc(gk5e->keybytes, gfp);
	if (!key.data)
		return -ENOMEM;

	DERIVE_Ke(server_key, rxgk_const_token_Ke, &token_key->Ke);
	DERIVE_Ki(server_key, rxgk_const_token_Ki, &token_key->Ki);
	ret = 0;
out_buf:
	kfree_sensitive(key.data);
	return ret;

out:
	rxgk_free_enc_keys(token_key);
	goto out;
}
