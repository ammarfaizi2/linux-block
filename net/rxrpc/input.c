// SPDX-License-Identifier: GPL-2.0-or-later
/* RxRPC packet reception
 *
 * Copyright (C) 2007, 2016, 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ar-internal.h"

/*
 * handle data received on the local endpoint
 * - may be called in interrupt context
 *
 * [!] Note that as this is called from the encap_rcv hook, the socket is not
 * held locked by the caller and nothing prevents sk_user_data on the UDP from
 * being cleared in the middle of processing this function.
 *
 * Called with the RCU read lock held from the IP layer via UDP.
 */
int rxrpc_input_packet(struct sock *udp_sk, struct sk_buff *skb)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxrpc_local *local = rcu_dereference_sk_user_data(udp_sk);

	if (unlikely(!local)) {
		kfree_skb(skb);
		return 0;
	}
	if (skb->tstamp == 0)
		skb->tstamp = ktime_get_real();

	rxrpc_new_skb(skb, rxrpc_skb_received);
	memset(sp, 0, sizeof(*sp));
	skb_queue_tail(&local->rx_queue, skb);
	rxrpc_wake_up_io_thread(local);
	return 0;
}

/*
 * Process event packets targeted at a local endpoint.
 */
static void rxrpc_input_version(struct rxrpc_local *local, struct sk_buff *skb)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	char v;

	_enter("");

	rxrpc_see_skb(skb, rxrpc_skb_seen);
	if (skb_copy_bits(skb, sizeof(struct rxrpc_wire_header), &v, 1) >= 0) {
		_proto("Rx VERSION { %02x }", v);
		if (v == 0)
			rxrpc_send_version_request(local, &sp->hdr, skb);
	}

	rxrpc_free_skb(skb, rxrpc_skb_freed);
}

/*
 * Extract the wire header from a packet and translate the byte order.
 */
static int rxrpc_extract_header(struct rxrpc_skb_priv *sp, struct sk_buff *skb)
{
	struct rxrpc_wire_header whdr;

	/* dig out the RxRPC connection details */
	if (skb_copy_bits(skb, 0, &whdr, sizeof(whdr)) < 0) {
		trace_rxrpc_rx_eproto(NULL, sp->hdr.serial,
				      tracepoint_string("bad_hdr"));
		return -EBADMSG;
	}

	sp->hdr.epoch		= ntohl(whdr.epoch);
	sp->hdr.cid		= ntohl(whdr.cid);
	sp->hdr.callNumber	= ntohl(whdr.callNumber);
	sp->hdr.seq		= ntohl(whdr.seq);
	sp->hdr.serial		= ntohl(whdr.serial);
	sp->hdr.flags		= whdr.flags;
	sp->hdr.type		= whdr.type;
	sp->hdr.userStatus	= whdr.userStatus;
	sp->hdr.securityIndex	= whdr.securityIndex;
	sp->hdr._rsvd		= ntohs(whdr._rsvd);
	sp->hdr.serviceId	= ntohs(whdr.serviceId);
	return 0;
}

/*
 * Process a socket buffer, distributing it to the appropriate connection or
 * call.
 */
static void rxrpc_input_one_packet(struct rxrpc_local *local, struct sk_buff *skb)
{
	struct rxrpc_connection *conn;
	struct rxrpc_channel *chan;
	struct rxrpc_call *call = NULL;
	struct rxrpc_skb_priv *sp;
	struct rxrpc_peer *peer = NULL;
	struct rxrpc_sock *rx = NULL;
	unsigned int channel;

	_enter("");

	skb_pull(skb, sizeof(struct udphdr));

	sp = rxrpc_skb(skb);
	if (sp->call) {
		trace_rxrpc_call_poked(sp->call);
		rxrpc_input_call_packet(sp->call, skb);
		rxrpc_put_call(sp->call, rxrpc_call_put_poke);
		goto discard;
	}

	/* dig out the RxRPC connection details */
	if (rxrpc_extract_header(sp, skb) < 0)
		goto bad_message;

	if (IS_ENABLED(CONFIG_AF_RXRPC_INJECT_LOSS)) {
		static int lose;
		if ((lose++ & 7) == 7) {
			trace_rxrpc_rx_lose(sp);
			rxrpc_free_skb(skb, rxrpc_skb_lost);
			return;
		}
	}

	trace_rxrpc_rx_packet(sp);

	switch (sp->hdr.type) {
	case RXRPC_PACKET_TYPE_VERSION:
		if (rxrpc_to_client(sp))
			goto discard;
		rxrpc_input_version(local, skb);
		goto out;

	case RXRPC_PACKET_TYPE_BUSY:
		if (rxrpc_to_server(sp))
			goto discard;
		fallthrough;
	case RXRPC_PACKET_TYPE_ACK:
	case RXRPC_PACKET_TYPE_ACKALL:
		if (sp->hdr.callNumber == 0)
			goto bad_message;
		fallthrough;
	case RXRPC_PACKET_TYPE_ABORT:
		break;

	case RXRPC_PACKET_TYPE_DATA:
		if (sp->hdr.callNumber == 0 ||
		    sp->hdr.seq == 0)
			goto bad_message;
		break;

	case RXRPC_PACKET_TYPE_CHALLENGE:
		if (rxrpc_to_server(sp))
			goto discard;
		break;
	case RXRPC_PACKET_TYPE_RESPONSE:
		if (rxrpc_to_client(sp))
			goto discard;
		break;

		/* Packet types 9-11 should just be ignored. */
	case RXRPC_PACKET_TYPE_PARAMS:
	case RXRPC_PACKET_TYPE_10:
	case RXRPC_PACKET_TYPE_11:
		goto discard;

	default:
		_proto("Rx Bad Packet Type %u", sp->hdr.type);
		goto bad_message;
	}

	if (sp->hdr.serviceId == 0)
		goto bad_message;

	if (rxrpc_to_server(sp)) {
		/* Weed out packets to services we're not offering.  Packets
		 * that would begin a call are explicitly rejected and the rest
		 * are just discarded.
		 */
		rx = rcu_dereference(local->service);
		if (!rx || (sp->hdr.serviceId != rx->srx.srx_service &&
			    sp->hdr.serviceId != rx->second_service)) {
			if (sp->hdr.type == RXRPC_PACKET_TYPE_DATA &&
			    sp->hdr.seq == 1)
				goto unsupported_service;
			goto discard;
		}
	}

	conn = rxrpc_find_connection_rcu(local, skb, &peer);
	if (conn) {
		if (sp->hdr.securityIndex != conn->security_ix)
			goto wrong_security;

		if (sp->hdr.serviceId != conn->service_id) {
			int old_id;

			if (!test_bit(RXRPC_CONN_PROBING_FOR_UPGRADE, &conn->flags))
				goto reupgrade;
			old_id = cmpxchg(&conn->service_id, conn->params.service_id,
					 sp->hdr.serviceId);

			if (old_id != conn->params.service_id &&
			    old_id != sp->hdr.serviceId)
				goto reupgrade;
		}

		if (sp->hdr.callNumber == 0) {
			/* Connection-level packet */
			_debug("CONN %p {%d}", conn, conn->debug_id);
			rxrpc_input_conn_packet(conn, skb);
			goto out;
		}

		if ((int)sp->hdr.serial - (int)conn->hi_serial > 0)
			conn->hi_serial = sp->hdr.serial;

		/* Call-bound packets are routed by connection channel. */
		channel = sp->hdr.cid & RXRPC_CHANNELMASK;
		chan = &conn->channels[channel];

		/* Ignore really old calls */
		if (sp->hdr.callNumber < chan->last_call)
			goto discard;

		if (sp->hdr.callNumber == chan->last_call) {
			if (chan->call ||
			    sp->hdr.type == RXRPC_PACKET_TYPE_ABORT)
				goto discard;

			/* For the previous service call, if completed
			 * successfully, we discard all further packets.
			 */
			if (rxrpc_conn_is_service(conn) &&
			    chan->last_type == RXRPC_PACKET_TYPE_ACK)
				goto discard;

			/* But otherwise we need to retransmit the final packet
			 * from data cached in the connection record.
			 */
			if (sp->hdr.type == RXRPC_PACKET_TYPE_DATA)
				trace_rxrpc_rx_data(chan->call_debug_id,
						    sp->hdr.seq,
						    sp->hdr.serial,
						    sp->hdr.flags);
			rxrpc_input_conn_packet(conn, skb);
			goto out;
		}

		call = rcu_dereference(chan->call);

		if (sp->hdr.callNumber > chan->call_id) {
			if (rxrpc_to_client(sp))
				goto reject_packet;
			if (call) {
				rxrpc_implicit_end_call(call, skb);
				chan->call = NULL;
				call = NULL;
			}
		}
	}

	if (!call || refcount_read(&call->ref) == 0) {
		if (rxrpc_to_client(sp) ||
		    sp->hdr.type != RXRPC_PACKET_TYPE_DATA)
			goto bad_message;
		if (sp->hdr.seq != 1)
			goto discard;
		call = rxrpc_new_incoming_call(local, rx, skb);
		if (!call)
			goto reject_packet;
	}

	/* Process a call packet; this either discards or passes on the ref
	 * elsewhere.
	 */
	if (!test_bit(RXRPC_CALL_RX_HEARD, &call->flags))
		set_bit(RXRPC_CALL_RX_HEARD, &call->flags);
	rxrpc_input_call_packet(call, skb);
	goto out;

discard:
	rxrpc_free_skb(skb, rxrpc_skb_freed);
out:
	trace_rxrpc_rx_done(0, 0);
	return;

wrong_security:
	trace_rxrpc_abort(0, "SEC", sp->hdr.cid, sp->hdr.callNumber, sp->hdr.seq,
			  RXKADINCONSISTENCY, EBADMSG);
	skb->priority = RXKADINCONSISTENCY;
	goto post_abort;

unsupported_service:
	trace_rxrpc_abort(0, "INV", sp->hdr.cid, sp->hdr.callNumber, sp->hdr.seq,
			  RX_INVALID_OPERATION, EOPNOTSUPP);
	skb->priority = RX_INVALID_OPERATION;
	goto post_abort;

reupgrade:
	trace_rxrpc_abort(0, "UPG", sp->hdr.cid, sp->hdr.callNumber, sp->hdr.seq,
			  RX_PROTOCOL_ERROR, EBADMSG);
	goto protocol_error;

bad_message:
	trace_rxrpc_abort(0, "BAD", sp->hdr.cid, sp->hdr.callNumber, sp->hdr.seq,
			  RX_PROTOCOL_ERROR, EBADMSG);
protocol_error:
	skb->priority = RX_PROTOCOL_ERROR;
post_abort:
	skb->mark = RXRPC_SKB_MARK_REJECT_ABORT;
reject_packet:
	trace_rxrpc_rx_done(skb->mark, skb->priority);
	rxrpc_reject_packet(local, skb);
	_leave(" [badmsg]");
	return;
}

/*
 * I/O and event handling thread.
 */
int rxrpc_io_thread(void *data)
{
	struct sk_buff_head rx_queue;
	struct rxrpc_local *local = data;
	struct sk_buff *skb;

	skb_queue_head_init(&rx_queue);

	set_user_nice(current, MIN_NICE);

	for (;;) {
		if (!skb_queue_empty(&local->rx_queue)) {
			spin_lock_irq(&local->rx_queue.lock);
			skb_queue_splice_tail_init(&local->rx_queue, &rx_queue);
			spin_unlock_irq(&local->rx_queue.lock);
		}

		while ((skb = __skb_dequeue(&rx_queue)))
			rxrpc_input_one_packet(local, skb);

		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		if (!skb_queue_empty(&local->rx_queue)) {
			__set_current_state(TASK_RUNNING);
			continue;
		}
		schedule();
	}

	__set_current_state(TASK_RUNNING);
	rxrpc_destroy_local(local);
	local->io_thread = NULL;
	return 0;
}
