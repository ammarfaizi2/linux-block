// SPDX-License-Identifier: GPL-2.0-or-later
/* RxGK transport key derivation.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/key-type.h>
#include <linux/slab.h>
#include <keys/rxrpc-type.h>
#include "ar-internal.h"
#include "rxgk_common.h"

#define round16(x) (((x) + 15) & ~15)

static void rxgk_free(struct rxgk_context *gk)
{
	if (gk->tx_Kc)
		crypto_free_shash(gk->tx_Kc);
	if (gk->rx_Kc)
		crypto_free_shash(gk->rx_Kc);
	crypto_krb5_free_enc_keys(&gk->tx_enc);
	crypto_krb5_free_enc_keys(&gk->rx_enc);
	crypto_krb5_free_enc_keys(&gk->resp_enc);
	kfree(gk);
}

void rxgk_put(struct rxgk_context *gk)
{
	if (gk && refcount_dec_and_test(&gk->usage))
		rxgk_free(gk);
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
				     struct krb5_buffer *TK,
				     gfp_t gfp)
{
	const struct krb5_enctype *krb5 = gk->krb5;
	struct krb5_buffer conn_info;
	unsigned int L = krb5->key_bytes;
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

	ret = crypto_krb5_calc_PRFplus(krb5, &rxgk->key, L, &conn_info, TK, gfp);
	kfree_sensitive(buffer);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Constants used to derive the keys and hmacs actually used for doing stuff.
 */
#define RXGK_CLIENT_ENC_PACKET		1026U // 0x402
#define RXGK_CLIENT_MIC_PACKET          1027U // 0x403
#define RXGK_SERVER_ENC_PACKET          1028U // 0x404
#define RXGK_SERVER_MIC_PACKET          1029U // 0x405
#define RXGK_CLIENT_ENC_RESPONSE        1030U // 0x406
#define RXGK_SERVER_ENC_TOKEN           1036U // 0x40c

/*
 * Set up the ciphers for the usage keys.
 */
static int rxgk_set_up_ciphers(struct rxrpc_connection *conn,
			       struct rxgk_context *gk,
			       const struct rxgk_key *rxgk,
			       gfp_t gfp)
{
	const struct krb5_enctype *krb5 = gk->krb5;
	struct krb5_buffer TK, key;
	bool service = rxrpc_conn_is_service(conn);
	int ret;
	u8 *buffer;

	buffer = kzalloc(krb5->key_bytes * 2, gfp);
	if (!buffer)
		return -ENOMEM;

	TK.len = krb5->key_bytes;
	TK.data = buffer;
	key.len = krb5->key_bytes;
	key.data = buffer + krb5->key_bytes;

	ret = rxgk_derive_transport_key(conn, gk, rxgk, &TK, gfp);
	if (ret < 0)
		goto out;

#define DERIVE_Kc(KEY, USAGE, KC)				   \
	do {							   \
		ret = crypto_krb5_get_Kc(krb5, KEY, USAGE, &key, KC, gfp); \
		if (ret < 0)						\
			goto out;					\
	} while (0)
#define DERIVE_Ke(KEY, USAGE, KE)				   \
	do {							   \
		ret = crypto_krb5_get_Ke(krb5, KEY, USAGE, &key, KE, gfp); \
		if (ret < 0)						\
			goto out;					\
	} while (0)
#define DERIVE_Ki(KEY, USAGE, KI)				   \
	do {							   \
		ret = crypto_krb5_get_Ki(krb5, KEY, USAGE, &key, KI, gfp); \
		if (ret < 0)						\
			goto out;					\
	} while (0)

	DERIVE_Ke(&TK, RXGK_CLIENT_ENC_RESPONSE, &gk->resp_enc.Ke);
	DERIVE_Ki(&TK, RXGK_CLIENT_ENC_RESPONSE, &gk->resp_enc.Ki);

	if (crypto_sync_skcipher_blocksize(gk->resp_enc.Ke) != krb5->block_len ||
	    crypto_shash_digestsize(gk->resp_enc.Ki) < krb5->cksum_len) {
		pr_notice("algo inconsistent with krb5 table %u!=%u or %u!=%u\n",
			  crypto_sync_skcipher_blocksize(gk->resp_enc.Ke), krb5->block_len,
			  crypto_shash_digestsize(gk->resp_enc.Ki), krb5->cksum_len);
		return -EINVAL;
	}

	if (service) {
		switch (conn->security_level) {
		case RXRPC_SECURITY_AUTH:
			DERIVE_Kc(&TK, RXGK_CLIENT_MIC_PACKET, &gk->rx_Kc);
			DERIVE_Kc(&TK, RXGK_SERVER_MIC_PACKET, &gk->tx_Kc);
			break;
		case RXRPC_SECURITY_ENCRYPT:
			DERIVE_Ke(&TK, RXGK_CLIENT_ENC_PACKET, &gk->rx_enc.Ke);
			DERIVE_Ki(&TK, RXGK_CLIENT_ENC_PACKET, &gk->rx_enc.Ki);
			DERIVE_Ke(&TK, RXGK_SERVER_ENC_PACKET, &gk->tx_enc.Ke);
			DERIVE_Ki(&TK, RXGK_SERVER_ENC_PACKET, &gk->tx_enc.Ki);
			break;
		}
	} else {
		switch (conn->security_level) {
		case RXRPC_SECURITY_AUTH:
			DERIVE_Kc(&TK, RXGK_CLIENT_MIC_PACKET, &gk->tx_Kc);
			DERIVE_Kc(&TK, RXGK_SERVER_MIC_PACKET, &gk->rx_Kc);
			break;
		case RXRPC_SECURITY_ENCRYPT:
			DERIVE_Ke(&TK, RXGK_CLIENT_ENC_PACKET, &gk->tx_enc.Ke);
			DERIVE_Ki(&TK, RXGK_CLIENT_ENC_PACKET, &gk->tx_enc.Ki);
			DERIVE_Ke(&TK, RXGK_SERVER_ENC_PACKET, &gk->rx_enc.Ke);
			DERIVE_Ki(&TK, RXGK_SERVER_ENC_PACKET, &gk->rx_enc.Ki);
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

	gk = kzalloc(sizeof(*gk), GFP_KERNEL);
	if (!gk)
		return ERR_PTR(-ENOMEM);
	refcount_set(&gk->usage, 1);
	gk->key		= key;
	gk->key_number	= key_number;

	gk->krb5 = crypto_krb5_find_enctype(key->enctype);
	if (!gk->krb5) {
		ret = -ENOPKG;
		goto err_tk;
	}

	ret = rxgk_set_up_ciphers(conn, gk, key, gfp);
	if (ret)
		goto err_tk;

	/* Set the remaining number of bytes encrypted with this key that may
	 * be transmitted before rekeying.  Note that the spec has been
	 * interpreted differently on this point...
	 */
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
int rxgk_set_up_token_cipher(const struct krb5_buffer *server_key,
			     struct krb5_enc_keys *token_key,
			     unsigned int enctype,
			     const struct krb5_enctype **_krb5,
			     gfp_t gfp)
{
	const struct krb5_enctype *krb5;
	struct krb5_buffer key;
	int ret;

	ret = -ENOPKG;
	krb5 = crypto_krb5_find_enctype(enctype);
	if (!krb5)
		goto out_buf;

	*_krb5 = krb5;

	key.len = krb5->key_bytes;
	key.data = kzalloc(krb5->key_bytes, gfp);
	if (!key.data)
		return -ENOMEM;

	DERIVE_Ke(server_key, RXGK_SERVER_ENC_TOKEN, &token_key->Ke);
	DERIVE_Ki(server_key, RXGK_SERVER_ENC_TOKEN, &token_key->Ki);
	ret = 0;
out_buf:
	kfree_sensitive(key.data);
	return ret;

out:
	crypto_krb5_free_enc_keys(token_key);
	goto out;
}
