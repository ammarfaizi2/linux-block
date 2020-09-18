// SPDX-License-Identifier: GPL-2.0-or-later
/* GSSAPI-based RxRPC security
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/key-type.h>
#include "ar-internal.h"
#include "rxgk_common.h"

/*
 * Parse the information from a server key
 */
static int rxgk_preparse_server_key(struct key_preparsed_payload *prep)
{
	const struct krb5_enctype *krb5;
	struct krb5_buffer *server_key = (void *)&prep->payload.data[2];
	unsigned int service, sec_class, kvno, enctype;
	int n = 0;

	_enter("%zu", prep->datalen);

	if (sscanf(prep->orig_description, "%u:%u:%u:%u%n",
		   &service, &sec_class, &kvno, &enctype, &n) != 4)
		return -EINVAL;

	if (prep->orig_description[n])
		return -EINVAL;

	krb5 = crypto_krb5_find_enctype(enctype);
	if (!krb5)
		return -ENOPKG;

	prep->payload.data[0] = (struct krb5_enctype *)krb5;

	if (prep->datalen != krb5->key_len)
		return -EKEYREJECTED;

	server_key->len = prep->datalen;
	server_key->data = kmemdup(prep->data, prep->datalen, GFP_KERNEL);
	if (!server_key->data)
		return -ENOMEM;

	_leave(" = 0");
	return 0;
}

static void rxgk_free_server_key(union key_payload *payload)
{
	struct krb5_buffer *server_key = (void *)&payload->data[2];

	kfree_sensitive(server_key->data);
}

static void rxgk_free_preparse_server_key(struct key_preparsed_payload *prep)
{
	rxgk_free_server_key(&prep->payload);
}

static void rxgk_destroy_server_key(struct key *key)
{
	rxgk_free_server_key(&key->payload);
}

static void rxgk_describe_server_key(const struct key *key, struct seq_file *m)
{
	const struct krb5_enctype *krb5 = key->payload.data[0];

	if (krb5)
		seq_printf(m, ": %s", krb5->name);
}

/*
 * Handle rekeying the connection when we see our limits overrun or when the
 * far side decided to rekey.
 *
 * Returns a ref on the context if successful or -ESTALE if the key is out of
 * date.
 */
static struct rxgk_context *rxgk_rekey(struct rxrpc_connection *conn,
				       const u16 *specific_key_number)
{
	struct rxgk_context *gk, *dead = NULL;
	unsigned int key_number, current_key, mask = ARRAY_SIZE(conn->rxgk.keys) - 1;
	bool crank = false;

	_enter("%d", specific_key_number ? *specific_key_number : -1);

	mutex_lock(&conn->security_lock);

	current_key = conn->rxgk.key_number;
	if (!specific_key_number) {
		key_number = current_key;
	} else {
		if (*specific_key_number == (u16)current_key)
			key_number = current_key;
		else if (*specific_key_number == (u16)(current_key - 1))
			key_number = current_key - 1;
		else if (*specific_key_number == (u16)(current_key + 1))
			goto crank_window;
		else
			goto bad_key;
	}

	gk = conn->rxgk.keys[key_number & mask];
	if (!gk)
		goto generate_key;
	if (!specific_key_number &&
	    test_bit(RXGK_TK_NEEDS_REKEY, &gk->flags))
		goto crank_window;

grab:
	refcount_inc(&gk->usage);
	mutex_unlock(&conn->security_lock);
	rxgk_put(dead);
	return gk;

crank_window:
	if (current_key == UINT_MAX)
		goto bad_key;
	if (current_key + 1 == UINT_MAX)
		set_bit(RXRPC_CONN_DONT_REUSE, &conn->flags);

	key_number = current_key + 1;
	if (WARN_ON(conn->rxgk.keys[key_number & mask]))
		goto bad_key;
	crank = true;

generate_key:
	gk = conn->rxgk.keys[current_key & mask];
	gk = rxgk_generate_transport_key(conn, gk->key, key_number, GFP_NOFS);
	if (IS_ERR(gk)) {
		mutex_unlock(&conn->security_lock);
		return gk;
	}

	write_lock(&conn->security_use_lock);
	if (crank) {
		current_key++;
		conn->rxgk.key_number = current_key;
		dead = conn->rxgk.keys[(current_key - 2) & mask];
		conn->rxgk.keys[(current_key - 2) & mask] = NULL;
	}
	conn->rxgk.keys[current_key & mask] = gk;
	write_unlock(&conn->security_use_lock);
	goto grab;

bad_key:
	mutex_unlock(&conn->security_lock);
	return ERR_PTR(-ESTALE);
}

/*
 * Get the specified keying context.
 *
 * Returns a ref on the context if successful or -ESTALE if the key is out of
 * date.
 */
static struct rxgk_context *rxgk_get_key(struct rxrpc_connection *conn,
					 const u16 *specific_key_number)
{
	struct rxgk_context *gk;
	unsigned int key_number, current_key, mask = ARRAY_SIZE(conn->rxgk.keys) - 1;

	_enter("{%u},%d",
	       conn->rxgk.key_number, specific_key_number ? *specific_key_number : -1);

	read_lock(&conn->security_use_lock);

	current_key = conn->rxgk.key_number;
	if (!specific_key_number) {
		key_number = current_key;
	} else {
		/* Only the bottom 16 bits of the key number are exposed in the
		 * header, so we try and keep the upper 16 bits in step.  The
		 * whole 32 bits are used to generate the TK.
		 */
		if (*specific_key_number == (u16)current_key)
			key_number = current_key;
		else if (*specific_key_number == (u16)(current_key - 1))
			key_number = current_key - 1;
		else if (*specific_key_number == (u16)(current_key + 1))
			goto rekey;
		else
			goto bad_key;
	}

	gk = conn->rxgk.keys[key_number & mask];
	if (!gk)
		goto slow_path;
	if (!specific_key_number &&
	    key_number < UINT_MAX) {
		if (time_after(jiffies, gk->expiry) ||
		    gk->bytes_remaining < 0) {
			set_bit(RXGK_TK_NEEDS_REKEY, &gk->flags);
			goto slow_path;
		}

		if (test_bit(RXGK_TK_NEEDS_REKEY, &gk->flags))
			goto slow_path;
	}

	refcount_inc(&gk->usage);
	read_unlock(&conn->security_use_lock);
	return gk;

rekey:
	_debug("rekey");
	if (current_key == UINT_MAX)
		goto bad_key;
	gk = conn->rxgk.keys[current_key & mask];
	if (gk)
		set_bit(RXGK_TK_NEEDS_REKEY, &gk->flags);
slow_path:
	read_unlock(&conn->security_use_lock);
	return rxgk_rekey(conn, specific_key_number);
bad_key:
	read_unlock(&conn->security_use_lock);
	return ERR_PTR(-ESTALE);
}

/*
 * initialise connection security
 */
static int rxgk_init_connection_security(struct rxrpc_connection *conn,
					 struct rxrpc_key_token *token)
{
	struct rxgk_context *gk;
	int ret;

	_enter("{%d,%u},{%x}",
	       conn->debug_id, conn->rxgk.key_number, key_serial(conn->key));

	conn->security_ix = token->security_index;
	conn->security_level = token->rxgk->level;

	if (rxrpc_conn_is_client(conn)) {
		conn->rxgk.start_time = ktime_get();
		do_div(conn->rxgk.start_time, 100);
	}

	gk = rxgk_generate_transport_key(conn, token->rxgk, conn->rxgk.key_number,
					 GFP_NOFS);
	if (IS_ERR(gk))
		return PTR_ERR(gk);
	conn->rxgk.keys[gk->key_number & 3] = gk;

	switch (conn->security_level) {
	case RXRPC_SECURITY_PLAIN:
	case RXRPC_SECURITY_AUTH:
	case RXRPC_SECURITY_ENCRYPT:
		break;
	default:
		ret = -EKEYREJECTED;
		goto error;
	}

	ret = 0;
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * Clean up the crypto on a call.
 */
static void rxgk_free_call_crypto(struct rxrpc_call *call)
{
}

/*
 * Work out how much data we can put in a packet.
 */
static int rxgk_how_much_data(struct rxrpc_call *call, size_t remain,
			      size_t *_buf_size, size_t *_data_size, size_t *_offset)
{
	struct rxgk_context *gk;
	enum krb5_crypto_mode mode;
	size_t shdr, buf_size, chunk, offset;

	switch (call->conn->security_level) {
	default:
		chunk = min_t(size_t, remain, RXRPC_JUMBO_DATALEN);
		buf_size = chunk;
		offset = 0;
		goto out;
	case RXRPC_SECURITY_AUTH:
		shdr = 0;
		mode = KRB5_CHECKSUM_MODE;
		break;
	case RXRPC_SECURITY_ENCRYPT:
		shdr = sizeof(struct rxgk_header);
		mode = KRB5_ENCRYPT_MODE;
		break;
	}

	gk = rxgk_get_key(call->conn, NULL);
	if (IS_ERR(gk))
		return PTR_ERR(gk);

	buf_size = RXRPC_JUMBO_DATALEN;
	chunk = crypto_krb5_how_much_data(gk->krb5, mode, false, &buf_size, &offset);
	chunk -= shdr;
	offset += shdr;
	rxgk_put(gk);

out:
	*_buf_size = buf_size;
	*_data_size = chunk;
	*_offset = offset;
	return 0;
}

/*
 * Integrity mode (sign a packet - level 1 security)
 */
static int rxgk_secure_packet_integrity(const struct rxrpc_call *call,
					struct rxgk_context *gk,
					struct rxrpc_txbuf *txb)
{
	struct rxgk_header *hdr;
	struct krb5_buffer metadata;
	unsigned int data_size = txb->len;
	int ret = -ENOMEM;

	_enter("");

	hdr = kzalloc(sizeof(*hdr), GFP_NOFS);
	if (!hdr)
		goto error_gk;

	hdr->epoch	= htonl(call->conn->proto.epoch);
	hdr->cid	= htonl(call->cid);
	hdr->call_number = htonl(call->call_id);
	hdr->seq	= htonl(txb->seq);
	hdr->sec_index	= htonl(call->security_ix);
	hdr->data_len	= htonl(data_size);

	metadata.len = sizeof(*hdr);
	metadata.data = hdr;
	ret = rxgk_get_mic_txb(gk->krb5, gk->tx_Kc, &metadata, txb,
			       0, sizeof(txb->data),
			       txb->sec_header, data_size);
	if (ret >= 0) {
		txb->len = ret;
		gk->bytes_remaining -= ret;
	}
	kfree(hdr);
error_gk:
	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;
}

/*
 * wholly encrypt a packet (level 2 security)
 */
static int rxgk_secure_packet_encrypted(const struct rxrpc_call *call,
					struct rxgk_context *gk,
					struct rxrpc_txbuf *txb)
{
	struct rxgk_header *hdr;
	unsigned int data_size = txb->len;
	unsigned int hdr_offset = txb->sec_header - sizeof(*hdr);
	int ret;

	_enter("%x", txb->len);

	/* Insert the header into the buffer. */
	hdr = (void *)txb->data + hdr_offset;
	hdr->epoch	 = htonl(call->conn->proto.epoch);
	hdr->cid	 = htonl(call->cid);
	hdr->call_number = htonl(call->call_id);
	hdr->seq	 = htonl(txb->seq);
	hdr->sec_index	 = htonl(call->security_ix);
	hdr->data_len	 = htonl(data_size);

	ret = rxgk_encrypt_txb(gk->krb5, &gk->tx_enc, txb,
			       0, sizeof(txb->data),
			       hdr_offset, sizeof(*hdr) + data_size,
			       false);
	if (ret >= 0) {
		txb->len = ret;
		gk->bytes_remaining -= ret;
	}

	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;
}

/*
 * checksum an RxRPC packet header
 */
static int rxgk_secure_packet(struct rxrpc_call *call, struct rxrpc_txbuf *txb)
{
	struct rxgk_context *gk;
	int ret;

	_enter("{%d{%x}},{#%u},%u,",
	       call->debug_id, key_serial(call->conn->key), txb->seq, txb->len);

	gk = rxgk_get_key(call->conn, NULL);
	if (IS_ERR(gk))
		return PTR_ERR(gk) == -ESTALE ? -EKEYREJECTED : PTR_ERR(gk);

	ret = key_validate(call->conn->key);
	if (ret < 0)
		return ret;

	txb->wire.cksum = htons(gk->key_number);

	switch (call->conn->security_level) {
	case RXRPC_SECURITY_PLAIN:
		rxgk_put(gk);
		return 0;
	case RXRPC_SECURITY_AUTH:
		return rxgk_secure_packet_integrity(call, gk, txb);
	case RXRPC_SECURITY_ENCRYPT:
		return rxgk_secure_packet_encrypted(call, gk, txb);
	default:
		rxgk_put(gk);
		return -EPERM;
	}
}

/*
 * Integrity mode (check the signature on a packet - level 1 security)
 */
static int rxgk_verify_packet_integrity(struct rxrpc_call *call,
					struct rxgk_context *gk,
					struct sk_buff *skb)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxgk_header *hdr;
	struct krb5_buffer metadata;
	unsigned int offset = sp->offset, len = sp->len;
	u32 ac;
	int ret = -ENOMEM;

	_enter("");

	hdr = kzalloc(sizeof(*hdr), GFP_NOFS);
	if (!hdr)
		return -ENOMEM;

	hdr->epoch	= htonl(call->conn->proto.epoch);
	hdr->cid	= htonl(call->cid);
	hdr->call_number = htonl(call->call_id);
	hdr->seq	= htonl(sp->hdr.seq);
	hdr->sec_index	= htonl(call->security_ix);
	hdr->data_len	= htonl(rxgk_where_is_the_data(gk->krb5, NULL, len));

	metadata.len = sizeof(*hdr);
	metadata.data = hdr;
	ret = rxgk_verify_mic_skb(gk->krb5, gk->rx_Kc, &metadata,
				  skb, &offset, &len, &ac);
	kfree(hdr);
	if (ret == -EPROTO) {
		rxrpc_abort_eproto(call, skb, ac,
				   rxgk_abort_1_verify_mic_eproto);
	} else {
		sp->offset = offset;
		sp->len = len;
	}

	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Decrypt an encrypted packet (level 2 security).
 */
static int rxgk_verify_packet_encrypted(struct rxrpc_call *call,
					struct rxgk_context *gk,
					struct sk_buff *skb)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxgk_header hdr;
	unsigned int offset = sp->offset, len = sp->len;
	int ret;
	u32 ac;

	_enter("");

	ret = rxgk_decrypt_skb(gk->krb5, &gk->rx_enc, skb, &offset, &len, &ac);
	if (ret == -EPROTO)
		rxrpc_abort_eproto(call, skb, ac, rxgk_abort_2_decrypt_eproto);
	if (ret < 0)
		goto error;

	if (len < sizeof(hdr)) {
		ret = rxrpc_abort_eproto(call, skb, RXGK_PACKETSHORT,
					 rxgk_abort_2_short_header);
		goto error;
	}

	/* Extract the header from the skb */
	ret = skb_copy_bits(skb, offset, &hdr, sizeof(hdr));
	if (ret < 0) {
		ret = rxrpc_abort_eproto(call, skb, RXGK_PACKETSHORT,
					 rxgk_abort_2_short_encdata);
		goto error;
	}
	offset += sizeof(hdr);
	len -= sizeof(hdr);

	if (ntohl(hdr.epoch)		!= call->conn->proto.epoch ||
	    ntohl(hdr.cid)		!= call->cid ||
	    ntohl(hdr.call_number)	!= call->call_id ||
	    ntohl(hdr.seq)		!= sp->hdr.seq ||
	    ntohl(hdr.sec_index)	!= call->security_ix ||
	    ntohl(hdr.data_len)		> len) {
		ret = rxrpc_abort_eproto(call, skb, RXGK_SEALED_INCON,
					 rxgk_abort_2_short_data);
		goto error;
	}

	sp->offset = offset;
	sp->len = ntohl(hdr.data_len);
	ret = 0;
error:
	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Verify the security on a received packet or subpacket (if part of a
 * jumbo packet).
 */
static int rxgk_verify_packet(struct rxrpc_call *call, struct sk_buff *skb)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxgk_context *gk;
	u16 key_number = sp->hdr.cksum;

	_enter("{%d{%x}},{#%u}",
	       call->debug_id, key_serial(call->conn->key), sp->hdr.seq);

	gk = rxgk_get_key(call->conn, &key_number);
	if (IS_ERR(gk)) {
		switch (PTR_ERR(gk)) {
		case -ESTALE:
			return rxrpc_abort_eproto(call, skb, RXGK_BADKEYNO,
						  rxgk_abort_bad_key_number);
		default:
			return PTR_ERR(gk);
		}
	}

	switch (call->conn->security_level) {
	case RXRPC_SECURITY_PLAIN:
		return 0;
	case RXRPC_SECURITY_AUTH:
		return rxgk_verify_packet_integrity(call, gk, skb);
	case RXRPC_SECURITY_ENCRYPT:
		return rxgk_verify_packet_encrypted(call, gk, skb);
	default:
		rxgk_put(gk);
		return -ENOANO;
	}
}

/*
 * issue a challenge
 */
static int rxgk_issue_challenge(struct rxrpc_connection *conn)
{
	struct rxrpc_wire_header whdr;
	struct msghdr msg;
	struct kvec iov[2];
	size_t len;
	u32 serial;
	int ret;

	_enter("{%d}", conn->debug_id);

	get_random_bytes(&conn->rxgk.nonce, sizeof(conn->rxgk.nonce));

	msg.msg_name	= &conn->peer->srx.transport;
	msg.msg_namelen	= conn->peer->srx.transport_len;
	msg.msg_control	= NULL;
	msg.msg_controllen = 0;
	msg.msg_flags	= 0;

	whdr.epoch	= htonl(conn->proto.epoch);
	whdr.cid	= htonl(conn->proto.cid);
	whdr.callNumber	= 0;
	whdr.seq	= 0;
	whdr.type	= RXRPC_PACKET_TYPE_CHALLENGE;
	whdr.flags	= conn->out_clientflag;
	whdr.userStatus	= 0;
	whdr.securityIndex = conn->security_ix;
	whdr._rsvd	= 0;
	whdr.serviceId	= htons(conn->service_id);

	iov[0].iov_base	= &whdr;
	iov[0].iov_len	= sizeof(whdr);
	iov[1].iov_base	= conn->rxgk.nonce;
	iov[1].iov_len	= sizeof(conn->rxgk.nonce);

	len = iov[0].iov_len + iov[1].iov_len;

	serial = atomic_inc_return(&conn->serial);
	whdr.serial = htonl(serial);

	ret = kernel_sendmsg(conn->local->socket, &msg, iov, 2, len);
	if (ret < 0) {
		trace_rxrpc_tx_fail(conn->debug_id, serial, ret,
				    rxrpc_tx_point_rxgk_challenge);
		return -EAGAIN;
	}

	conn->peer->last_tx_at = ktime_get_seconds();
	trace_rxrpc_tx_packet(conn->debug_id, &whdr,
			      rxrpc_tx_point_rxgk_challenge);
	_leave(" = 0");
	return 0;
}

/*
 * Send a response packet.
 */
static int rxgk_send_response(struct rxrpc_connection *conn,
			      struct rxrpc_txbuf *txb)
{
	struct msghdr msg;
	struct kvec iov[1];
	size_t len;
	u32 serial;
	int ret, i;

	_enter("");

	msg.msg_name	= &conn->peer->srx.transport;
	msg.msg_namelen	= conn->peer->srx.transport_len;
	msg.msg_control	= NULL;
	msg.msg_controllen = 0;
	msg.msg_flags	= 0;

	iov[0].iov_base	= &txb->wire;
	iov[0].iov_len	= sizeof(txb->wire) + txb->len;

	len = 0;
	for (i = 0; i < ARRAY_SIZE(iov); i++)
		len += iov[i].iov_len;

	serial = atomic_inc_return(&conn->serial);
	txb->wire.serial = htonl(serial);

	ret = kernel_sendmsg(conn->local->socket, &msg,
			     iov, ARRAY_SIZE(iov), len);
	if (ret < 0) {
		trace_rxrpc_tx_fail(conn->debug_id, serial, ret,
				    rxrpc_tx_point_rxgk_response);
		return -EAGAIN;
	}

	conn->peer->last_tx_at = ktime_get_seconds();
	_leave(" = 0");
	return 0;
}

/*
 * Construct the authenticator to go in the response packet
 *
 * struct RXGK_Authenticator {
 *	opaque nonce[20];
 *	opaque appdata<>;
 *	RXGK_Level level;
 *	unsigned int epoch;
 *	unsigned int cid;
 *	unsigned int call_numbers<>;
 * };
 */
static void rxgk_construct_authenticator(struct rxrpc_connection *conn,
					 const u8 *nonce, __be32 *xdr)
{
	memcpy(xdr, nonce, 20);
	xdr += 5;
	*xdr++ = htonl(0); /* appdata len */
	*xdr++ = htonl(conn->security_level);
	*xdr++ = htonl(conn->proto.epoch);
	*xdr++ = htonl(conn->proto.cid);
	*xdr++ = htonl(4); /* # call_numbers */
	*xdr++ = htonl(conn->channels[0].call_counter);
	*xdr++ = htonl(conn->channels[1].call_counter);
	*xdr++ = htonl(conn->channels[2].call_counter);
	*xdr   = htonl(conn->channels[3].call_counter);
}

/*
 * Construct the response.
 *
 * struct RXGK_Response {
 *	rxgkTime start_time;
 *	RXGK_Data token;
 *	opaque authenticator<RXGK_MAXAUTHENTICATOR>
 * };
 */
static int rxgk_construct_response(struct rxrpc_connection *conn,
				   struct sk_buff *challenge,
				   const u8 *nonce)
{
	struct rxgk_context *gk;
	struct rxrpc_txbuf *txb;
	size_t resp_len, auth_len, authx_len, auth_offset, authx_offset;
	__be32 *xdr;
	int ret;

	gk = rxgk_get_key(conn, NULL);
	if (IS_ERR(gk))
		return PTR_ERR(gk);

	auth_len = 20 + 4 /* appdatalen */ + 12 + (1 + 4) * 4;
	authx_len = crypto_krb5_how_much_buffer(gk->krb5,
						KRB5_ENCRYPT_MODE, true,
						auth_len, &auth_offset);

	resp_len  = 8;
	resp_len += 4 + xdr_round_up(gk->key->ticket.len);
	resp_len += 4 + xdr_round_up(authx_len);

	ret = -ENOMEM;
	txb = rxrpc_alloc_response_txbuf(conn, challenge);
	if (!txb)
		goto error_gk;

	txb->wire.cksum = htons(gk->key_number);
	xdr = (void *)txb->data;

	*xdr++ = htonl(upper_32_bits(conn->rxgk.start_time));
	*xdr++ = htonl(lower_32_bits(conn->rxgk.start_time));
	*xdr++ = htonl(gk->key->ticket.len);
	memcpy(xdr, gk->key->ticket.data, xdr_round_up(gk->key->ticket.len));
	xdr += xdr_round_up(gk->key->ticket.len) / sizeof(*xdr);
	*xdr++ = htonl(authx_len);

	authx_offset = (u8 *)xdr - txb->data;
	auth_offset += authx_offset;

	xdr = (void *)txb->data + auth_offset;
	rxgk_construct_authenticator(conn, nonce, xdr);

	ret = rxgk_encrypt_txb(gk->krb5, &gk->resp_enc, txb,
			       authx_offset, authx_len,
			       auth_offset, auth_len, false);
	if (ret < 0)
		goto error;

	txb->len = authx_offset + ret;

	ret = rxgk_send_response(conn, txb);
error:
	rxrpc_put_txbuf(txb, rxrpc_txbuf_put_response_tx);
error_gk:
	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Respond to a challenge packet
 */
static int rxgk_respond_to_challenge(struct rxrpc_connection *conn,
				     struct sk_buff *skb)
{
	u8 nonce[20];

	_enter("{%d,%x}", conn->debug_id, key_serial(conn->key));

	if (!conn->key)
		return rxrpc_abort_conn(conn, skb, RX_PROTOCOL_ERROR, -EPROTO,
					rxgk_abort_chall_no_key);

	if (key_validate(conn->key) < 0)
		return rxrpc_abort_conn(conn, skb, RXGK_EXPIRED, -EPROTO,
					rxgk_abort_chall_key_expired);

	if (skb_copy_bits(skb, sizeof(struct rxrpc_wire_header),
			  nonce, sizeof(nonce)) < 0)
		return rxrpc_abort_conn(conn, skb, RXGK_PACKETSHORT, -EPROTO,
					rxgk_abort_chall_short);

	return rxgk_construct_response(conn, skb, nonce);
}

/*
 * Verify the authenticator.
 *
 * struct RXGK_Authenticator {
 *	opaque nonce[20];
 *	opaque appdata<>;
 *	RXGK_Level level;
 *	unsigned int epoch;
 *	unsigned int cid;
 *	unsigned int call_numbers<>;
 * };
 */
static int rxgk_do_verify_authenticator(struct rxrpc_connection *conn,
					const struct krb5_enctype *krb5,
					struct sk_buff *skb,
					__be32 *p, __be32 *end)
{
	u32 app_len, call_count, level, epoch, cid, i;

	_enter("");

	if (memcmp(p, conn->rxgk.nonce, 20) != 0)
		return rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
					rxgk_abort_resp_bad_nonce);
	p += 20 / sizeof(__be32);

	app_len	= ntohl(*p++);
	if (app_len > (end - p) * sizeof(__be32))
		return rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
					rxgk_abort_resp_short_applen);

	p += xdr_round_up(app_len) / sizeof(__be32);
	if (end - p < 4)
		return rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
					rxgk_abort_resp_short_applen);

	level	= ntohl(*p++);
	epoch	= ntohl(*p++);
	cid	= ntohl(*p++);
	call_count = ntohl(*p++);

	if (level	!= conn->security_level ||
	    epoch	!= conn->proto.epoch ||
	    cid		!= conn->proto.cid ||
	    call_count	> 4)
		return rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
					rxgk_abort_resp_bad_param);

	if (end - p < call_count)
		return rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
					rxgk_abort_resp_short_call_list);

	for (i = 0; i < call_count; i++) {
		u32 call_id = ntohl(*p++);

		if (call_id > INT_MAX)
			return rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
						rxgk_abort_resp_bad_callid);

		if (call_id < conn->channels[i].call_counter)
			return rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
						rxgk_abort_resp_call_ctr);

		if (call_id > conn->channels[i].call_counter) {
			if (conn->channels[i].call)
				return rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
							rxgk_abort_resp_call_state);

			conn->channels[i].call_counter = call_id;
		}
	}

	_leave(" = 0");
	return 0;
}

/*
 * Extract the authenticator and verify it.
 */
static int rxgk_verify_authenticator(struct rxrpc_connection *conn,
				     const struct krb5_enctype *krb5,
				     struct sk_buff *skb,
				     unsigned int auth_offset, unsigned int auth_len)
{
	void *auth;
	__be32 *p;
	int ret;

	auth = kmalloc(auth_len, GFP_NOFS);
	if (!auth)
		return -ENOMEM;

	ret = skb_copy_bits(skb, auth_offset, auth, auth_len);
	if (ret < 0) {
		ret = rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EPROTO,
				       rxgk_abort_resp_short_auth);
		goto error;
	}

	p = auth;
	ret = rxgk_do_verify_authenticator(conn, krb5, skb, p, p + auth_len);
error:
	kfree(auth);
	return ret;
}

/*
 * Verify a response.
 *
 * struct RXGK_Response {
 *	rxgkTime	start_time;
 *	RXGK_Data	token;
 *	opaque		authenticator<RXGK_MAXAUTHENTICATOR>
 * };
 */
static int rxgk_verify_response(struct rxrpc_connection *conn,
				struct sk_buff *skb)
{
	const struct krb5_enctype *krb5;
	struct rxrpc_key_token *token;
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct krb5_enc_keys token_enc = {};
	struct rxgk_response rhdr;
	struct rxgk_context *gk;
	struct key *key = NULL;
	unsigned int offset = sizeof(struct rxrpc_wire_header);
	unsigned int len = skb->len - sizeof(struct rxrpc_wire_header);
	unsigned int token_offset, token_len;
	unsigned int auth_offset, auth_len;
	__be32 xauth_len;
	int ret, ec;

	_enter("{%d}", conn->debug_id);

	/* Parse the RXGK_Response object */
	if (sizeof(rhdr) + sizeof(__be32) > len)
		goto short_packet;

	if (skb_copy_bits(skb, offset, &rhdr, sizeof(rhdr)) < 0)
		goto short_packet;
	offset	+= sizeof(rhdr);
	len	-= sizeof(rhdr);

	token_offset	= offset;
	token_len	= ntohl(rhdr.token_len);
	if (xdr_round_up(token_len) + sizeof(__be32) > len)
		goto short_packet;

	offset	+= xdr_round_up(token_len);
	len	-= xdr_round_up(token_len);

	if (skb_copy_bits(skb, offset, &xauth_len, sizeof(xauth_len)) < 0)
		goto short_packet;
	offset	+= sizeof(xauth_len);
	len	-= sizeof(xauth_len);

	auth_offset	= offset;
	auth_len	= ntohl(xauth_len);
	if (auth_len < len)
		goto short_packet;
	if (auth_len & 3)
		goto inconsistent;
	if (auth_len < 20 + 9 * 4)
		goto auth_too_short;

	/* We need to extract and decrypt the token and instantiate a session
	 * key for it.  This bit, however, is application-specific.  If
	 * possible, we use a default parser, but we might end up bumping this
	 * to the app to deal with - which might mean a round trip to
	 * userspace.
	 */
	ret = rxgk_extract_token(conn, skb, token_offset, token_len, &key);
	if (ret < 0)
		goto out;

	/* We now have a key instantiated from the decrypted ticket.  We can
	 * pass this to the application so that they can parse the ticket
	 * content and we can use the session key it contains to derive the
	 * keys we need.
	 *
	 * Note that we have to switch enctype at this point as the enctype of
	 * the ticket doesn't necessarily match that of the transport.
	 */
	token = key->payload.data[0];
	conn->security_level = token->rxgk->level;
	conn->rxgk.start_time = __be64_to_cpu(rhdr.start_time);

	gk = rxgk_generate_transport_key(conn, token->rxgk, sp->hdr.cksum, GFP_NOFS);
	if (IS_ERR(gk)) {
		ret = PTR_ERR(gk);
		goto cant_get_token;
	}

	krb5 = gk->krb5;

	/* Decrypt, parse and verify the authenticator. */
	ret = rxgk_decrypt_skb(krb5, &gk->resp_enc, skb,
			       &auth_offset, &auth_len, &ec);
	if (ret < 0) {
		rxrpc_abort_conn(conn, skb, RXGK_SEALED_INCON, ret,
				 rxgk_abort_resp_auth_dec);
		goto out;
	}

	ret = rxgk_verify_authenticator(conn, krb5, skb, auth_offset, auth_len);
	if (ret < 0)
		goto out;

	conn->key = key;
	key = NULL;
	ret = 0;
out:
	key_put(key);
	crypto_krb5_free_enc_keys(&token_enc);
	_leave(" = %d", ret);
	return ret;

inconsistent:
	ret = rxrpc_abort_conn(conn, skb, RXGK_INCONSISTENCY, -EPROTO,
			       rxgk_abort_resp_xdr_align);
	goto out;
auth_too_short:
	ret = rxrpc_abort_conn(conn, skb, RXGK_PACKETSHORT, -EPROTO,
			       rxgk_abort_resp_short_auth);
	goto out;
short_packet:
	ret = rxrpc_abort_conn(conn, skb, RXGK_PACKETSHORT, -EPROTO,
			       rxgk_abort_resp_short_packet);
	goto out;

cant_get_token:
	switch (ret) {
	case -ENOMEM:
		goto temporary_error;
	case -EINVAL:
		ret = rxrpc_abort_conn(conn, skb, RXGK_NOTAUTH, -EKEYREJECTED,
				       rxgk_abort_resp_internal_error);
		goto out;
	case -ENOPKG:
		ret = rxrpc_abort_conn(conn, skb, RXGK_BADETYPE, -EKEYREJECTED,
				       rxgk_abort_resp_nopkg);
		goto out;
	}

temporary_error:
	/* Ignore the response packet if we got a temporary error such as
	 * ENOMEM.  We just want to send the challenge again.  Note that we
	 * also come out this way if the ticket decryption fails.
	 */
	goto out;
}

/*
 * clear the connection security
 */
static void rxgk_clear(struct rxrpc_connection *conn)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(conn->rxgk.keys); i++)
		rxgk_put(conn->rxgk.keys[i]);
}

/*
 * Initialise the RxGK security service.
 */
static int rxgk_init(void)
{
	return 0;
}

/*
 * Clean up the RxGK security service.
 */
static void rxgk_exit(void)
{
}

/*
 * RxRPC YFS GSSAPI-based security
 */
const struct rxrpc_security rxgk_yfs = {
	.name				= "yfs-rxgk",
	.security_index			= RXRPC_SECURITY_YFS_RXGK,
	.no_key_abort			= RXGK_NOTAUTH,
	.init				= rxgk_init,
	.exit				= rxgk_exit,
	.preparse_server_key		= rxgk_preparse_server_key,
	.free_preparse_server_key	= rxgk_free_preparse_server_key,
	.destroy_server_key		= rxgk_destroy_server_key,
	.describe_server_key		= rxgk_describe_server_key,
	.init_connection_security	= rxgk_init_connection_security,
	.how_much_data			= rxgk_how_much_data,
	.secure_packet			= rxgk_secure_packet,
	.verify_packet			= rxgk_verify_packet,
	.free_call_crypto		= rxgk_free_call_crypto,
	.issue_challenge		= rxgk_issue_challenge,
	.respond_to_challenge		= rxgk_respond_to_challenge,
	.verify_response		= rxgk_verify_response,
	.clear				= rxgk_clear,
	.default_decode_ticket		= rxgk_yfs_decode_ticket,
};
