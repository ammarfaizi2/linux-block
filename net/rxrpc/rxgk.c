// SPDX-License-Identifier: GPL-2.0-or-later
/* GSSAPI-based RxRPC security
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/key-type.h>
#include <keys/rxrpc-type.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include "ar-internal.h"
#include "rxgk_common.h"

struct rxgk_header {
	__be32	epoch;
	__be32	cid;
	__be32	call_number;
	__be32	seq;
	__be32	sec_index;
	__be32	data_len;
} __packed;

struct rxgk_response {
	__be64	start_time;
	__be32	token_len;
} __packed;

/*
 * Parse the information from a server key
 */
static int rxgk_preparse_server_key(struct key_preparsed_payload *prep)
{
	const struct rxgk_krb5_enctype *gk5e;
	struct rxgk_buffer *server_key = (void *)&prep->payload.data[2];
	unsigned int service, sec_class, kvno, enctype;
	int n = 0;

	_enter("%zu", prep->datalen);

	if (sscanf(prep->orig_description, "%u:%u:%u:%u%n",
		   &service, &sec_class, &kvno, &enctype, &n) != 4)
		return -EINVAL;

	if (prep->orig_description[n])
		return -EINVAL;

	gk5e = rxgk_find_enctype(enctype);
	if (!gk5e)
		return -ENOPKG;

	prep->payload.data[0] = (struct rxgk_krb5_enctype *)gk5e;

	if (prep->datalen != gk5e->keylength)
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
	struct rxgk_buffer *server_key = (void *)&payload->data[2];

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
	const struct rxgk_krb5_enctype *gk5e = key->payload.data[0];

	if (gk5e)
		seq_printf(m, ": %s", gk5e->name);
}

/*
 * Handle rekeying the connection when the we see our limits overrun or when
 * the far side decided to rekey.
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

	mutex_lock(&conn->rekeying_lock);

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
	mutex_unlock(&conn->rekeying_lock);
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
		mutex_unlock(&conn->rekeying_lock);
		return gk;
	}

	write_lock(&conn->security_lock);
	if (crank) {
		current_key++;
		conn->rxgk.key_number = current_key;
		dead = conn->rxgk.keys[(current_key - 2) & mask];
		conn->rxgk.keys[(current_key - 2) & mask] = NULL;
	}
	conn->rxgk.keys[current_key & mask] = gk;
	write_unlock(&conn->security_lock);
	goto grab;

bad_key:
	mutex_unlock(&conn->rekeying_lock);
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

	read_lock(&conn->security_lock);

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
	read_unlock(&conn->security_lock);
	return gk;

rekey:
	_debug("rekey");
	if (current_key == UINT_MAX)
		goto bad_key;
	gk = conn->rxgk.keys[current_key & mask];
	if (gk)
		set_bit(RXGK_TK_NEEDS_REKEY, &gk->flags);
slow_path:
	read_unlock(&conn->security_lock);
	return rxgk_rekey(conn, specific_key_number);
bad_key:
	read_unlock(&conn->security_lock);
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
	       conn->debug_id, conn->rxgk.key_number, key_serial(conn->params.key));

	conn->security_ix = token->security_index;
	conn->params.security_level = token->rxgk->level;

	if (rxrpc_conn_is_client(conn)) {
		conn->rxgk.start_time = ktime_get();
		do_div(conn->rxgk.start_time, 100);
	}

	gk = rxgk_generate_transport_key(conn, token->rxgk, conn->rxgk.key_number,
					 GFP_NOFS);
	if (IS_ERR(gk))
		return PTR_ERR(gk);
	conn->rxgk.keys[gk->key_number & 3] = gk;

	switch (conn->params.security_level) {
	case RXRPC_SECURITY_PLAIN:
		break;
	case RXRPC_SECURITY_AUTH:
		conn->rxgk.data_offset = gk->gk5e->cksumlength;
		break;
	case RXRPC_SECURITY_ENCRYPT:
		conn->rxgk.data_offset = gk->gk5e->conflen + sizeof(struct rxgk_header);
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
 * Integrity mode (sign a packet - level 1 security)
 */
static int rxgk_secure_packet_integrity(const struct rxrpc_call *call,
					struct rxgk_context *gk,
					struct sk_buff *skb, u32 data_size)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxgk_header *hdr;
	struct rxgk_buffer metadata;
	int ret = -ENOMEM;

	_enter("");

	hdr = kzalloc(sizeof(*hdr), GFP_NOFS);
	if (!hdr)
		goto error_gk;

	hdr->epoch	= htonl(call->conn->proto.epoch);
	hdr->cid	= htonl(call->cid);
	hdr->call_number = htonl(call->call_id);
	hdr->seq	= htonl(sp->hdr.seq);
	hdr->sec_index	= htonl(call->security_ix);
	hdr->data_len	= htonl(data_size);

	metadata.len = sizeof(*hdr);
	metadata.data = hdr;
	ret = gk->gk5e->scheme->get_mic_skb(gk->gk5e, gk->tx_Kc, &metadata, skb,
					    gk->gk5e->cksumlength, data_size);
	if (ret >= 0)
		gk->bytes_remaining -= ret;
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
					struct sk_buff *skb, u32 data_size)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxgk_header hdr;
	int ret;

	_enter("%x,%x", skb->len, data_size);

	/* Insert the header into the skb */
	hdr.epoch	= htonl(call->conn->proto.epoch);
	hdr.cid		= htonl(call->cid);
	hdr.call_number = htonl(call->call_id);
	hdr.seq		= htonl(sp->hdr.seq);
	hdr.sec_index	= htonl(call->security_ix);
	hdr.data_len	= htonl(data_size);

	ret = skb_store_bits(skb, gk->gk5e->conflen, &hdr, sizeof(hdr));
	if (ret < 0)
		goto error;

	/* Increase the buffer size to allow for the checksum to be written in */
	skb->len += gk->gk5e->cksumlength;

	ret = gk->gk5e->scheme->encrypt_skb(gk->gk5e, &gk->tx_enc, skb,
					    gk->gk5e->conflen, sizeof(hdr) + data_size,
					    false);
	if (ret >= 0)
		gk->bytes_remaining -= ret;

error:
	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;
}

/*
 * checksum an RxRPC packet header
 */
static int rxgk_secure_packet(struct rxrpc_call *call,
			      struct sk_buff *skb,
			      size_t data_size)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxgk_context *gk;
	int ret;

	sp = rxrpc_skb(skb);

	_enter("{%d{%x}},{#%u},%zu,",
	       call->debug_id, key_serial(call->conn->params.key),
	       sp->hdr.seq, data_size);

	gk = rxgk_get_key(call->conn, NULL);
	if (IS_ERR(gk))
		return PTR_ERR(gk) == -ESTALE ? -EKEYREJECTED : PTR_ERR(gk);

	ret = key_validate(call->conn->params.key);
	if (ret < 0)
		return ret;

	sp->hdr.cksum = gk->key_number;

	switch (call->conn->params.security_level) {
	case RXRPC_SECURITY_PLAIN:
		rxgk_put(gk);
		return 0;
	case RXRPC_SECURITY_AUTH:
		return rxgk_secure_packet_integrity(call, gk, skb, data_size);
	case RXRPC_SECURITY_ENCRYPT:
		return rxgk_secure_packet_encrypted(call, gk, skb, data_size);
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
					struct sk_buff *skb,
					unsigned int offset, unsigned int len,
					rxrpc_seq_t seq)
{
	struct rxgk_header *hdr;
	struct rxgk_buffer metadata;
	bool aborted;
	u32 ac;
	int ret = -ENOMEM;

	_enter("");

	hdr = kzalloc(sizeof(*hdr), GFP_NOFS);
	if (!hdr)
		goto error;

	hdr->epoch	= htonl(call->conn->proto.epoch);
	hdr->cid	= htonl(call->cid);
	hdr->call_number = htonl(call->call_id);
	hdr->seq	= htonl(seq);
	hdr->sec_index	= htonl(call->security_ix);
	hdr->data_len	= htonl(len - gk->gk5e->cksumlength);

	metadata.len = sizeof(*hdr);
	metadata.data = hdr;
	ret = gk->gk5e->scheme->verify_mic_skb(call, gk->gk5e, gk->rx_Kc, &metadata,
					       skb, &offset, &len, &ac);
	kfree(hdr);
	if (ret < 0) {
		if (ret == -EPROTO) {
			aborted = rxrpc_abort_eproto(call, skb, "rxgk_2_vfy",
						     "V1V", ac);
			goto protocol_error;
		}
		goto error;
	}

error:
	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;

protocol_error:
	if (aborted)
		rxrpc_send_abort_packet(call);
	ret = -EPROTO;
	goto error;
}

/*
 * Decrypt an encrypted packet (level 2 security).
 */
static int rxgk_verify_packet_encrypted(struct rxrpc_call *call,
					struct rxgk_context *gk,
					struct sk_buff *skb,
					unsigned int offset, unsigned int len,
					rxrpc_seq_t seq)
{
	struct rxgk_header hdr;
	bool aborted;
	int ret;
	u32 ac;

	_enter("");

	ret = gk->gk5e->scheme->decrypt_skb(call, gk->gk5e, &gk->rx_enc,
					    skb, &offset, &len, &ac);
	if (ret < 0) {
		if (ret == -EPROTO) {
			aborted = rxrpc_abort_eproto(call, skb, "rxgk_2_dec",
						     "V2D", ac);
			goto protocol_error;
		}
		goto error;
	}

	if (len < sizeof(hdr)) {
		aborted = rxrpc_abort_eproto(call, skb, "rxgk_2_hdr",
					     "V2L", RXGK_PACKETSHORT);
		goto protocol_error;
	}

	/* Extract the header from the skb */
	ret = skb_copy_bits(skb, offset, &hdr, sizeof(hdr));
	if (ret < 0)
		goto error;
	len -= sizeof(hdr);

	if (ntohl(hdr.epoch)		!= call->conn->proto.epoch ||
	    ntohl(hdr.cid)		!= call->cid ||
	    ntohl(hdr.call_number)	!= call->call_id ||
	    ntohl(hdr.seq)		!= seq ||
	    ntohl(hdr.sec_index)	!= call->security_ix ||
	    ntohl(hdr.data_len)		> len) {
		aborted = rxrpc_abort_eproto(call, skb, "rxgk_2_hdr", "V2H",
					     RXGK_SEALED_INCON);
		goto protocol_error;
	}

	ret = 0;

error:
	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;

protocol_error:
	if (aborted)
		rxrpc_send_abort_packet(call);
	ret = -EPROTO;
	goto error;
}

/*
 * Verify the security on a received packet or subpacket (if part of a
 * jumbo packet).
 */
static int rxgk_verify_packet(struct rxrpc_call *call, struct sk_buff *skb,
			      unsigned int offset, unsigned int len,
			      rxrpc_seq_t seq, u16 key_number)
{
	struct rxgk_context *gk;
	bool aborted;

	_enter("{%d{%x}},{#%u}",
	       call->debug_id, key_serial(call->conn->params.key), seq);

	gk = rxgk_get_key(call->conn, &key_number);
	if (IS_ERR(gk)) {
		switch (PTR_ERR(gk)) {
		case -ESTALE:
			aborted = rxrpc_abort_eproto(call, skb, "rxgk_csum", "VKY",
						     RXGK_BADKEYNO);
			gk = NULL;
			goto protocol_error;
		default:
			return PTR_ERR(gk);
		}
	}

	switch (call->conn->params.security_level) {
	case RXRPC_SECURITY_PLAIN:
		return 0;
	case RXRPC_SECURITY_AUTH:
		return rxgk_verify_packet_integrity(call, gk, skb, offset, len, seq);
	case RXRPC_SECURITY_ENCRYPT:
		return rxgk_verify_packet_encrypted(call, gk, skb, offset, len, seq);
	default:
		rxgk_put(gk);
		return -ENOANO;
	}

protocol_error:
	if (aborted)
		rxrpc_send_abort_packet(call);
	rxgk_put(gk);
	return -EPROTO;
}

/*
 * Locate the data contained in a packet that was partially encrypted.
 */
static void rxgk_locate_data_1(struct rxrpc_call *call, struct sk_buff *skb,
			       unsigned int *_offset, unsigned int *_len)
{
	*_offset += call->conn->rxgk.data_offset;
	*_len -= call->conn->rxgk.data_offset;
}

/*
 * Locate the data contained in a packet that was completely encrypted.
 */
static void rxgk_locate_data_2(struct rxrpc_call *call, struct sk_buff *skb,
			       unsigned int *_offset, unsigned int *_len)
{
	unsigned int off = call->conn->rxgk.data_offset - sizeof(__be32);
	__be32 data_length_be;
	u32 data_length;

	if (skb_copy_bits(skb, *_offset + off, &data_length_be, sizeof(u32)) < 0)
		BUG();
	data_length = ntohl(data_length_be);
	*_offset += call->conn->rxgk.data_offset;
	*_len = data_length;
}

/*
 * Locate the data contained in an already decrypted packet.
 */
static void rxgk_locate_data(struct rxrpc_call *call, struct sk_buff *skb,
			     unsigned int *_offset, unsigned int *_len)
{
	switch (call->conn->params.security_level) {
	case RXRPC_SECURITY_AUTH:
		rxgk_locate_data_1(call, skb, _offset, _len);
		return;
	case RXRPC_SECURITY_ENCRYPT:
		rxgk_locate_data_2(call, skb, _offset, _len);
		return;
	default:
		return;
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

	msg.msg_name	= &conn->params.peer->srx.transport;
	msg.msg_namelen	= conn->params.peer->srx.transport_len;
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
	_proto("Tx CHALLENGE %%%u", serial);

	ret = kernel_sendmsg(conn->params.local->socket, &msg, iov, 2, len);
	if (ret < 0) {
		trace_rxrpc_tx_fail(conn->debug_id, serial, ret,
				    rxrpc_tx_point_rxgk_challenge);
		return -EAGAIN;
	}

	conn->params.peer->last_tx_at = ktime_get_seconds();
	trace_rxrpc_tx_packet(conn->debug_id, &whdr,
			      rxrpc_tx_point_rxgk_challenge);
	_leave(" = 0");
	return 0;
}

/*
 * Send a response packet.
 */
static int rxgk_send_response(struct rxrpc_connection *conn,
			      struct sk_buff *skb)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxrpc_wire_header whdr;
	struct msghdr msg;
	struct kvec iov[2];
	size_t len;
	u32 serial;
	int ret, i;

	_enter("");

	msg.msg_name	= &conn->params.peer->srx.transport;
	msg.msg_namelen	= conn->params.peer->srx.transport_len;
	msg.msg_control	= NULL;
	msg.msg_controllen = 0;
	msg.msg_flags	= 0;

	memset(&whdr, 0, sizeof(whdr));
	whdr.epoch	= htonl(sp->hdr.epoch);
	whdr.cid	= htonl(sp->hdr.cid);
	whdr.type	= RXRPC_PACKET_TYPE_RESPONSE;
	whdr.flags	= sp->hdr.flags;
	whdr.securityIndex = sp->hdr.securityIndex;
	whdr.cksum	= htons(sp->hdr.cksum);
	whdr.serviceId	= htons(sp->hdr.serviceId);

	iov[0].iov_base	= &whdr;
	iov[0].iov_len	= sizeof(whdr);
	iov[1].iov_base	= skb->head;
	iov[1].iov_len	= skb->len;

	len = 0;
	for (i = 0; i < ARRAY_SIZE(iov); i++)
		len += iov[i].iov_len;

	serial = atomic_inc_return(&conn->serial);
	whdr.serial = htonl(serial);
	_proto("Tx RESPONSE %%%u", serial);

	ret = kernel_sendmsg(conn->params.local->socket, &msg,
			     iov, ARRAY_SIZE(iov), len);
	if (ret < 0) {
		trace_rxrpc_tx_fail(conn->debug_id, serial, ret,
				    rxrpc_tx_point_rxgk_response);
		return -EAGAIN;
	}

	conn->params.peer->last_tx_at = ktime_get_seconds();
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
					 const u8 *nonce,
					 struct sk_buff *skb)
{
	__be32 xdr[9];

	__skb_put_data(skb, nonce, 20);

	xdr[0] = htonl(0); /* appdata len */
	xdr[1] = htonl(conn->params.security_level);
	xdr[2] = htonl(conn->proto.epoch);
	xdr[3] = htonl(conn->proto.cid);
	xdr[4] = htonl(4); /* # call_numbers */
	xdr[5] = htonl(conn->channels[0].call_counter);
	xdr[6] = htonl(conn->channels[1].call_counter);
	xdr[7] = htonl(conn->channels[2].call_counter);
	xdr[8] = htonl(conn->channels[3].call_counter);

	__skb_put_data(skb, xdr, sizeof(xdr));
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
	struct rxrpc_skb_priv *csp = rxrpc_skb(challenge), *rsp;
	struct rxgk_context *gk;
	struct sk_buff *skb;
	unsigned short resp_len, auth_len, pad_len, enc_len, auth_pad_len, authx_len;
	unsigned short auth_offset;
	__be64 start_time;
	__be32 tmp;
	void *p;
	int ret;

	gk = rxgk_get_key(conn, NULL);
	if (IS_ERR(gk))
		return PTR_ERR(gk);

	auth_len = 20 + 4 /* appdatalen */ + 12 + (1 + 4) * 4;
	if (gk->gk5e->pad) {
		enc_len = round_up(gk->gk5e->conflen + auth_len, gk->gk5e->blocksize);
		pad_len = enc_len - (gk->gk5e->conflen + auth_len);
	} else {
		enc_len = gk->gk5e->conflen + auth_len;
		pad_len = 0;
	}
	authx_len = enc_len + gk->gk5e->cksumlength;
	auth_pad_len = xdr_round_up(authx_len) - authx_len;

	resp_len  = 8;
	resp_len += 4 + xdr_round_up(gk->key->ticket.len);
	resp_len += 4 + xdr_round_up(authx_len);

	ret = -ENOMEM;
	skb = alloc_skb(resp_len, GFP_NOFS);
	if (!skb)
		goto error_gk;

	rsp = rxrpc_skb(skb);
	rsp->hdr = csp->hdr;
	rsp->hdr.flags = conn->out_clientflag;
	rsp->hdr.cksum = gk->key_number;

	start_time = cpu_to_be64(conn->rxgk.start_time);
	p = __skb_put_data(skb, &start_time, 8);

	tmp = htonl(gk->key->ticket.len);
	__skb_put_data(skb, &tmp, 4);
	__skb_put_data(skb, gk->key->ticket.data, xdr_round_up(gk->key->ticket.len));
	tmp = htonl(authx_len);
	__skb_put_data(skb, &tmp, 4);
	//authx_offset = skb->len; -- This is where the secure region starts
	__skb_put_zero(skb, gk->gk5e->conflen);
	auth_offset = skb->len;
	rxgk_construct_authenticator(conn, nonce, skb);
	__skb_put_zero(skb, pad_len + gk->gk5e->cksumlength + auth_pad_len);

	ret = gk->gk5e->scheme->encrypt_skb(gk->gk5e, &gk->resp_enc, skb,
					    auth_offset, auth_len, false);
	if (ret < 0)
		goto error;

	ret = rxgk_send_response(conn, skb);
error:
	kfree_skb(skb);
error_gk:
	rxgk_put(gk);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Respond to a challenge packet
 */
static int rxgk_respond_to_challenge(struct rxrpc_connection *conn,
				     struct sk_buff *skb,
				     u32 *_abort_code)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	const char *eproto;
	u32 abort_code;
	u8 nonce[20];
	int ret;

	_enter("{%d,%x}", conn->debug_id, key_serial(conn->params.key));

	eproto = tracepoint_string("chall_no_key");
	abort_code = RX_PROTOCOL_ERROR;
	if (!conn->params.key)
		goto protocol_error;

	abort_code = RXGK_EXPIRED;
	ret = key_validate(conn->params.key);
	if (ret < 0)
		goto other_error;

	eproto = tracepoint_string("chall_short");
	abort_code = RXGK_PACKETSHORT;
	if (skb_copy_bits(skb, sizeof(struct rxrpc_wire_header),
			  nonce, sizeof(nonce)) < 0)
		goto protocol_error;

	_proto("Rx CHALLENGE %%%u { n=%20phN }", sp->hdr.serial, nonce);

	ret = rxgk_construct_response(conn, skb, nonce);
	if (ret < 0)
		goto error;
	return ret;

protocol_error:
	trace_rxrpc_rx_eproto(NULL, sp->hdr.serial, eproto);
	ret = -EPROTO;
other_error:
	*_abort_code = abort_code;
error:
	return ret;
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
static int rxgk_verify_authenticator(struct rxrpc_connection *conn,
				     const struct rxgk_krb5_enctype *gk5e,
				     struct sk_buff *skb,
				     unsigned int auth_offset, unsigned int auth_len,
				     u32 *_abort_code, const char **_eproto)
{
	void *auth;
	__be32 *p, *end;
	u32 app_len, call_count, level, epoch, cid, i;
	int ret;

	_enter("");

	auth = kmalloc(auth_len, GFP_NOFS);
	if (!auth)
		return -ENOMEM;

	ret = skb_copy_bits(skb, auth_offset, auth, auth_len);
	if (ret < 0)
		goto error;

	*_eproto = tracepoint_string("rxgk_rsp_nonce");
	p = auth;
	end = auth + auth_len;
	if (memcmp(auth, conn->rxgk.nonce, 20) != 0)
		goto bad_auth;
	p += 20 / sizeof(__be32);

	*_eproto = tracepoint_string("rxgk_rsp_applen");
	app_len	= ntohl(*p++);
	if (app_len > (end - p) * sizeof(__be32))
		goto bad_auth;
	p += xdr_round_up(app_len) / sizeof(__be32);
	if (end - p < 4)
		goto bad_auth;
	level	= ntohl(*p++);
	epoch	= ntohl(*p++);
	cid	= ntohl(*p++);
	call_count = ntohl(*p++);

	*_eproto = tracepoint_string("rxgk_rsp_params");
	if (level	!= conn->params.security_level ||
	    epoch	!= conn->proto.epoch ||
	    cid		!= conn->proto.cid ||
	    call_count	> 4)
		goto bad_auth;
	if (end - p < call_count)
		goto bad_auth;

	spin_lock(&conn->bundle->channel_lock);
	for (i = 0; i < call_count; i++) {
		struct rxrpc_call *call;
		u32 call_id = ntohl(*p++);

		*_eproto = tracepoint_string("rxgk_rsp_callid");
		if (call_id > INT_MAX)
			goto bad_auth_unlock;

		*_eproto = tracepoint_string("rxgk_rsp_callctr");
		if (call_id < conn->channels[i].call_counter)
			goto bad_auth_unlock;

		*_eproto = tracepoint_string("rxgk_rsp_callst");
		if (call_id > conn->channels[i].call_counter) {
			call = rcu_dereference_protected(
				conn->channels[i].call,
				lockdep_is_held(&conn->bundle->channel_lock));
			if (call && call->state < RXRPC_CALL_COMPLETE)
				goto bad_auth_unlock;
			conn->channels[i].call_counter = call_id;
		}
	}
	spin_unlock(&conn->bundle->channel_lock);
	ret = 0;
error:
	kfree(auth);
	_leave(" = %d", ret);
	return ret;

bad_auth_unlock:
	spin_unlock(&conn->bundle->channel_lock);
bad_auth:
	*_abort_code = RXGK_NOTAUTH;
	ret = -EPROTO;
	goto error;
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
				struct sk_buff *skb,
				u32 *_abort_code)
{
	const struct rxgk_krb5_enctype *gk5e;
	struct rxrpc_key_token *token;
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxgk_enc_keys token_enc = {};
	struct rxgk_context *gk;
	struct key *key = NULL;
	const char *eproto;
	unsigned int offset = sizeof(struct rxrpc_wire_header);
	unsigned int len = skb->len - sizeof(struct rxrpc_wire_header);
	unsigned int token_offset, token_len;
	unsigned int auth_offset, auth_len;
	__be32 xauth_len;
	u32 abort_code;
	int ret;

	struct rxgk_response rhdr;

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
	ret = rxgk_extract_token(conn, skb, token_offset, token_len, &key,
				 &abort_code, &eproto);
	if (ret < 0)
		goto protocol_error;

	/* We now have a key instantiated from the decrypted ticket.  We can
	 * pass this to the application so that they can parse the ticket
	 * content and we can use the session key it contains to derive the
	 * keys we need.
	 *
	 * Note that we have to switch enctype at this point as the enctype of
	 * the ticket doesn't necessarily match that of the transport.
	 */
	token = key->payload.data[0];
	conn->params.security_level = token->rxgk->level;
	conn->rxgk.start_time = __be64_to_cpu(rhdr.start_time);

	gk = rxgk_generate_transport_key(conn, token->rxgk, sp->hdr.cksum, GFP_NOFS);
	if (IS_ERR(gk)) {
		ret = PTR_ERR(gk);
		goto cant_get_token;
	}

	gk5e = gk->gk5e;

	/* Decrypt, parse and verify the authenticator. */
	eproto = tracepoint_string("rxgk_rsp_dec_auth");
	ret = gk5e->scheme->decrypt_skb(NULL, gk5e, &gk->resp_enc, skb,
					&auth_offset, &auth_len, &abort_code);
	if (ret < 0)
		goto protocol_error;

	ret = rxgk_verify_authenticator(conn, gk5e, skb, auth_offset, auth_len,
					&abort_code, &eproto);
	if (ret < 0)
		goto protocol_error;

	conn->params.key = key;
	key = NULL;
	ret = 0;
out:
	key_put(key);
	rxgk_free_enc_keys(&token_enc);
	_leave(" = %d", ret);
	return ret;

inconsistent:
	eproto = tracepoint_string("rxgk_rsp_xdr_align");
	abort_code = RXGK_INCONSISTENCY;
	ret = -EPROTO;
	goto protocol_error;
auth_too_short:
	eproto = tracepoint_string("rxgk_rsp_short_auth");
	abort_code = RXGK_PACKETSHORT;
	ret = -EPROTO;
	goto protocol_error;
short_packet:
	eproto = tracepoint_string("rxgk_rsp_short");
	abort_code = RXGK_PACKETSHORT;
	ret = -EPROTO;
protocol_error:
	trace_rxrpc_rx_eproto(NULL, sp->hdr.serial, eproto);
	*_abort_code = abort_code;
	goto out;

cant_get_token:
	switch (ret) {
	case -ENOMEM:
		goto temporary_error;
	case -EINVAL:
		eproto = tracepoint_string("rxgk_rsp_internal_error");
		abort_code = RXGK_NOTAUTH;
		ret = -EKEYREJECTED;
		goto protocol_error;
	case -ENOPKG:
		eproto = tracepoint_string("rxgk_rsp_nopkg");
		abort_code = RXGK_BADETYPE;
		ret = -EKEYREJECTED;
		goto protocol_error;
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
	rxgk_selftest();
	return 0;
}

/*
 * Clean up the RxGK security service.
 */
static void rxgk_exit(void)
{
}

/*
 * RxRPC OpenAFS GSSAPI-based security
 */
const struct rxrpc_security rxgk_openafs = {
	.name				= "rxgk",
	.security_index			= RXRPC_SECURITY_RXGK,
	.no_key_abort			= RXGK_NOTAUTH,
	.init				= rxgk_init,
	.exit				= rxgk_exit,
	.preparse_server_key		= rxgk_preparse_server_key,
	.free_preparse_server_key	= rxgk_free_preparse_server_key,
	.destroy_server_key		= rxgk_destroy_server_key,
	.describe_server_key		= rxgk_describe_server_key,
	.init_connection_security	= rxgk_init_connection_security,
	.secure_packet			= rxgk_secure_packet,
	.verify_packet			= rxgk_verify_packet,
	.free_call_crypto		= rxgk_free_call_crypto,
	.locate_data			= rxgk_locate_data,
	.issue_challenge		= rxgk_issue_challenge,
	.respond_to_challenge		= rxgk_respond_to_challenge,
	.verify_response		= rxgk_verify_response,
	.clear				= rxgk_clear,
	.default_decode_ticket		= rxgk_openafs_decode_ticket,
};

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
	.secure_packet			= rxgk_secure_packet,
	.verify_packet			= rxgk_verify_packet,
	.free_call_crypto		= rxgk_free_call_crypto,
	.locate_data			= rxgk_locate_data,
	.issue_challenge		= rxgk_issue_challenge,
	.respond_to_challenge		= rxgk_respond_to_challenge,
	.verify_response		= rxgk_verify_response,
	.clear				= rxgk_clear,
	.default_decode_ticket		= rxgk_yfs_decode_ticket,
};
