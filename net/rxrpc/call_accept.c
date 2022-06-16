// SPDX-License-Identifier: GPL-2.0-or-later
/* incoming call handling
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/errqueue.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/icmp.h>
#include <linux/gfp.h>
#include <linux/circ_buf.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include <net/ip.h>
#include "ar-internal.h"

static void rxrpc_dummy_notify(struct sock *sk, struct rxrpc_call *call,
			       unsigned long user_call_ID)
{
}

/*
 * Preallocate a single service call, connection and peer and, if possible,
 * give them a user ID and attach the user's side of the ID to them.
 */
static int rxrpc_service_preallocate(struct rxrpc_sock *rx)
{
	struct rxrpc_service *b = rx->service;
	struct rxrpc_net *rxnet = rxrpc_net(sock_net(&rx->sk));
	unsigned int head, tail, size = RXRPC_BACKLOG_MAX;
	int max = b->max_tba;

	head = b->peer_backlog_head;
	tail = READ_ONCE(b->peer_backlog_tail);
	while (CIRC_CNT(head, tail, size) < max) {
		struct rxrpc_peer *peer =
			rxrpc_alloc_peer(rx->local, GFP_KERNEL,
					 rxrpc_peer_new_prealloc);
		if (!peer)
			return -ENOMEM;
		b->peer_backlog[head++] = peer;
		head &= size - 1;
		smp_store_release(&b->peer_backlog_head, head);
	}

	head = b->conn_backlog_head;
	tail = READ_ONCE(b->conn_backlog_tail);
	while (CIRC_CNT(head, tail, size) < max) {
		struct rxrpc_connection *conn;

		conn = rxrpc_prealloc_service_connection(rxnet, GFP_KERNEL);
		if (!conn)
			return -ENOMEM;

		b->conn_backlog[head++] = conn;
		head &= size - 1;
		smp_store_release(&b->conn_backlog_head, head);
	}

	head = b->call_backlog_head;
	tail = READ_ONCE(b->call_backlog_tail);
	while (CIRC_CNT(head, tail, size) < max) {
		struct rxrpc_call *call;
		unsigned int debug_id = 0;

		if (!b->preallocate_call)
			debug_id = atomic_inc_return(&rxrpc_debug_id);

		call = rxrpc_alloc_call(rx, GFP_KERNEL, debug_id,
					b->preallocate_call);
		if (!call)
			return -ENOMEM;
		__set_bit(RXRPC_CALL_EV_INITIAL_PING, &call->events);
		__set_bit(RXRPC_CALL_IS_SERVICE, &call->flags);
		call->notify_rx = b->notify_rx;
		rxrpc_set_call_state(call, RXRPC_CALL_SERVER_PREALLOC);

		if (b->kernel_sock) {
			write_lock(&rx->call_lock);
			list_add(&call->sock_link, &rx->sock_calls);
			write_unlock(&rx->call_lock);
		} else {
			refcount_inc(&b->ref);
			call->service = b;
		}

		spin_lock(&rxnet->call_lock);
		list_add_tail_rcu(&call->link, &rxnet->calls);
		spin_unlock(&rxnet->call_lock);

		rxrpc_see_call(call, rxrpc_call_new_prealloc_service);

		b->call_backlog[head++] = call;
		head &= size - 1;
		smp_store_release(&b->call_backlog_head, head);
	}

	return 0;
}

/*
 * Attempt to add a user call ID to the preallocation ring.
 */
static int rxrpc_service_charge_user_call_id(struct rxrpc_sock *rx,
					     unsigned long user_call_ID)
{
	struct rxrpc_service *b = rx->service;
	struct rxrpc_call *xcall;
	struct rb_node *p;
	unsigned int head, tail, size = RXRPC_BACKLOG_MAX;
	unsigned int i;
	int ret = -EBADSLT, max = b->max_tba;

	_enter("%lx", user_call_ID);

	if (!b)
		return -EINVAL;

	write_lock(&rx->call_lock);

	/* Check the user ID isn't already in use in the active tree. */
	p = rx->calls.rb_node;
	while (p) {
		xcall = rb_entry(p, struct rxrpc_call, sock_node);
		if (user_call_ID < xcall->user_call_ID)
			p = p->rb_left;
		else if (user_call_ID > xcall->user_call_ID)
			p = p->rb_right;
		else
			goto err;
	}

	/* We also need to check the preallocation ring. */
	for (i = 0; i < size; i++)
		if (user_call_ID == rx->call_id_backlog[i])
			goto err;

	ret = -ENOBUFS;
	head = rx->call_id_backlog_head;
	tail = READ_ONCE(rx->call_id_backlog_tail);

	if (CIRC_CNT(head, tail, size) >= max)
		goto err;

	rx->call_id_backlog[head & (size - 1)] = user_call_ID;
	smp_store_release(&rx->call_id_backlog_head, (head + 1) & (size - 1));

	if (list_empty(&rx->accept_link)) {
		spin_lock(&b->incoming_lock);
		if (list_empty(&rx->accept_link))
			list_add_tail(&rx->accept_link, &b->waiting_sockets);
		spin_unlock(&b->incoming_lock);
	}
	ret = 0;

err:
	write_unlock(&rx->call_lock);
	return ret;
}

/*
 * Pick an ID for an incoming call and attach it to the socket.  This is only
 * used for sockets opened by userspace.  Kernel sockets get the user ID set
 * during preallocation.
 */
void rxrpc_user_accept_incoming_call(struct rxrpc_sock *rx)
{
	struct rxrpc_service *b = rx->service;
	struct rxrpc_call *xcall, *call;
	struct rb_node *parent, **pp;
	unsigned int head, tail, size = RXRPC_BACKLOG_MAX;

	if (CIRC_CNT(rx->call_id_backlog_head,
		     rx->call_id_backlog_tail, size) == 0)
		return;

	write_lock(&rx->call_lock);

	/* Obtain an ID from the preallocation ring. */
	head = smp_load_acquire(&rx->call_id_backlog_head);
	tail = rx->call_id_backlog_tail;

	if (CIRC_CNT(head, tail, size) == 0) {
		write_unlock(&rx->call_lock);
		return;
	}

	spin_lock(&b->incoming_lock);

	call = list_first_entry_or_null(&b->to_be_accepted,
					struct rxrpc_call, recvmsg_link);
	if (!call) {
		spin_unlock(&b->incoming_lock);
		write_unlock(&rx->call_lock);
		return;
	}

	spin_lock(&rx->recvmsg_lock);
	rxrpc_get_call(call, rxrpc_call_get_userid);
	call->user_call_ID = rx->call_id_backlog[tail];
	rcu_assign_pointer(call->socket, rx);
	/* recvmsg_link mustn't be seen to be empty. */
	list_move_tail(&call->recvmsg_link, &rx->recvmsg_q);
	b->nr_tba--;
	rx->nr_recvmsg++;
	spin_unlock(&rx->recvmsg_lock);

	rx->call_id_backlog[tail] = 0;
	tail = (tail + 1) & (size - 1);
	smp_store_release(&rx->call_id_backlog_tail, tail);

	if (CIRC_CNT(head, tail, size) == 0)
		list_del_init(&rx->accept_link);

	spin_unlock(&b->incoming_lock);

	rxrpc_see_call_aux(call, call->user_call_ID, rxrpc_call_see_accepted);

	/* Insert the ID */
	set_bit(RXRPC_CALL_HAS_USERID, &call->flags);

	pp = &rx->calls.rb_node;
	parent = NULL;
	while (*pp) {
		parent = *pp;
		xcall = rb_entry(parent, struct rxrpc_call, sock_node);
		if (call->user_call_ID < xcall->user_call_ID)
			pp = &(*pp)->rb_left;
		else if (call->user_call_ID > xcall->user_call_ID)
			pp = &(*pp)->rb_right;
		else
			goto id_in_use;
	}

	rb_link_node(&call->sock_node, parent, pp);
	rb_insert_color(&call->sock_node, &rx->calls);

	list_add(&call->sock_link, &rx->sock_calls);
	rx->nr_sock_calls++;

	write_unlock(&rx->call_lock);

	_leave(" [%d -> %lx]", call->debug_id, call->user_call_ID);
	return;

id_in_use:
	WARN_ON(1);
	write_unlock(&rx->call_lock);
	rxrpc_cleanup_call(call);
	return;
}

/*
 * Dispose of a service record.
 */
void rxrpc_put_service(struct rxrpc_net *rxnet, struct rxrpc_service *b)
{
	if (b && refcount_dec_and_test(&b->ref)) {
		key_put(b->securities);
		kfree_rcu(b, rcu);
	}
}

/*
 * Discard the preallocation on a service.
 */
void rxrpc_deactivate_service(struct rxrpc_sock *rx)
{
	struct rxrpc_service *b = rx->service;
	struct rxrpc_net *rxnet = rxrpc_net(sock_net(&rx->sk));
	unsigned int size = RXRPC_BACKLOG_MAX, head, tail;

	if (!refcount_dec_and_test(&rx->service->active))
		return;

	/* Now that active is 0, make sure that there aren't any incoming calls
	 * being set up before we clear the preallocation buffers.
	 */
	spin_lock(&b->incoming_lock);
	spin_unlock(&b->incoming_lock);

	mutex_lock(&rx->local->bind_lock);
	write_lock(&rx->local->services_lock);
	list_del(&b->local_link);
	write_unlock(&rx->local->services_lock);
	mutex_unlock(&rx->local->bind_lock);

	head = b->peer_backlog_head;
	tail = b->peer_backlog_tail;
	while (CIRC_CNT(head, tail, size) > 0) {
		struct rxrpc_peer *peer = b->peer_backlog[tail];
		rxrpc_put_local(peer->local, rxrpc_local_put_prealloc_peer);
		kfree(peer);
		tail = (tail + 1) & (size - 1);
	}

	head = b->conn_backlog_head;
	tail = b->conn_backlog_tail;
	while (CIRC_CNT(head, tail, size) > 0) {
		struct rxrpc_connection *conn = b->conn_backlog[tail];
		write_lock(&rxnet->conn_lock);
		list_del(&conn->link);
		list_del(&conn->proc_link);
		write_unlock(&rxnet->conn_lock);
		kfree(conn);
		if (atomic_dec_and_test(&rxnet->nr_conns))
			wake_up_var(&rxnet->nr_conns);
		tail = (tail + 1) & (size - 1);
	}

	head = b->call_backlog_head;
	tail = b->call_backlog_tail;
	while (CIRC_CNT(head, tail, size) > 0) {
		struct rxrpc_call *call = b->call_backlog[tail];

		rxrpc_see_call_aux(call, call->user_call_ID,
				   rxrpc_call_see_discard);
		if (b->discard_new_call) {
			_debug("discard %lx", call->user_call_ID);
			b->discard_new_call(call, call->user_call_ID);
			if (call->notify_rx)
				call->notify_rx = rxrpc_dummy_notify;
			rxrpc_put_call(call, rxrpc_call_put_kernel);
		}

		/* list_empty() must return false in rxrpc_notify_socket() */
		call->recvmsg_link.next = NULL;
		call->recvmsg_link.prev = NULL;
		rxrpc_call_completed(call);
		set_bit(RXRPC_CALL_RELEASED, &call->flags);
		list_del_init(&call->sock_link);
		rxrpc_put_call(call, rxrpc_call_put_discard_prealloc);
		tail = (tail + 1) & (size - 1);
	}

	while (!list_empty(&b->to_be_accepted)) {
		struct rxrpc_call *call =
			list_entry(b->to_be_accepted.next,
				   struct rxrpc_call, accept_link);
		list_del(&call->accept_link);
		rxrpc_propose_abort(call, RX_CALL_DEAD, -ECONNRESET,
				    rxrpc_abort_call_sock_release_tba);
		rxrpc_put_call(call, rxrpc_call_put_release_sock_tba);
	}
}

/*
 * Allocate a new incoming call from the prealloc pool, along with a connection
 * and a peer as necessary.
 */
static struct rxrpc_call *rxrpc_alloc_incoming_call(struct rxrpc_service *b,
						    struct rxrpc_local *local,
						    struct rxrpc_peer *peer,
						    struct rxrpc_connection *conn,
						    const struct rxrpc_security *sec,
						    struct sockaddr_rxrpc *peer_srx,
						    struct sk_buff *skb)
	__must_hold(&b->incoming_lock)
	__must_hold(&local->services_lock)
{
	struct rxrpc_call *call;
	unsigned short call_head, conn_head, peer_head;
	unsigned short call_tail, conn_tail, peer_tail;
	unsigned short call_count, conn_count;

	/* #calls >= #conns >= #peers must hold true. */
	call_head = smp_load_acquire(&b->call_backlog_head);
	call_tail = b->call_backlog_tail;
	call_count = CIRC_CNT(call_head, call_tail, RXRPC_BACKLOG_MAX);
	conn_head = smp_load_acquire(&b->conn_backlog_head);
	conn_tail = b->conn_backlog_tail;
	conn_count = CIRC_CNT(conn_head, conn_tail, RXRPC_BACKLOG_MAX);
	ASSERTCMP(conn_count, >=, call_count);
	peer_head = smp_load_acquire(&b->peer_backlog_head);
	peer_tail = b->peer_backlog_tail;
	ASSERTCMP(CIRC_CNT(peer_head, peer_tail, RXRPC_BACKLOG_MAX), >=,
		  conn_count);

	if (call_count == 0)
		return NULL;

	if (!conn) {
		if (peer && !rxrpc_get_peer_maybe(peer, rxrpc_peer_get_service_conn))
			peer = NULL;
		if (!peer) {
			peer = b->peer_backlog[peer_tail];
			peer->srx = *peer_srx;
			b->peer_backlog[peer_tail] = NULL;
			smp_store_release(&b->peer_backlog_tail,
					  (peer_tail + 1) &
					  (RXRPC_BACKLOG_MAX - 1));

			rxrpc_new_incoming_peer(local, peer);
		}

		/* Now allocate and set up the connection */
		conn = b->conn_backlog[conn_tail];
		b->conn_backlog[conn_tail] = NULL;
		smp_store_release(&b->conn_backlog_tail,
				  (conn_tail + 1) & (RXRPC_BACKLOG_MAX - 1));
		conn->local = rxrpc_get_local(local, rxrpc_local_get_prealloc_conn);
		conn->peer = peer;
		rxrpc_see_connection(conn, rxrpc_conn_see_new_service_conn);
		rxrpc_new_incoming_connection(b, conn, sec, skb);
	} else {
		rxrpc_get_connection(conn, rxrpc_conn_get_service_conn);
		atomic_inc(&conn->active);
	}

	/* And now we can allocate and set up a new call */
	call = b->call_backlog[call_tail];
	b->call_backlog[call_tail] = NULL;
	smp_store_release(&b->call_backlog_tail,
			  (call_tail + 1) & (RXRPC_BACKLOG_MAX - 1));

	rxrpc_see_call(call, rxrpc_call_see_accept);
	call->local = rxrpc_get_local(conn->local, rxrpc_local_get_call);
	call->conn = conn;
	call->security = conn->security;
	call->security_ix = conn->security_ix;
	call->peer = rxrpc_get_peer(conn->peer, rxrpc_peer_get_accept);
	call->dest_srx = peer->srx;
	call->cong_ssthresh = call->peer->cong_ssthresh;
	call->tx_last_sent = ktime_get_real();
	return call;
}

/*
 * Set up a new incoming call.  Called from the I/O thread.
 *
 * If this is for a kernel service, when we allocate the call, it will have
 * three refs on it: (1) the kernel service, (2) the user_call_ID tree, (3) the
 * retainer ref obtained from the backlog buffer.  Prealloc calls for userspace
 * services only have the ref from the backlog buffer.
 *
 * If we want to report an error, we mark the skb with the packet type and
 * abort code and return false.
 */
bool rxrpc_new_incoming_call(struct rxrpc_local *local,
			     struct rxrpc_peer *peer,
			     struct rxrpc_connection *conn,
			     struct sockaddr_rxrpc *peer_srx,
			     struct sk_buff *skb)
{
	const struct rxrpc_security *sec = NULL;
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	struct rxrpc_service *b;
	struct rxrpc_call *call = NULL;
	unsigned int i;

	_enter("");

	/* Don't set up a call for anything other than a DATA packet. */
	if (sp->hdr.type != RXRPC_PACKET_TYPE_DATA)
		return rxrpc_protocol_error(skb, rxrpc_eproto_no_service_call);
	if (list_empty(&local->services))
		goto unsupported_service;

	read_lock(&local->services_lock);

	/* Weed out packets to services we're not offering.  Packets that would
	 * begin a call are explicitly rejected and the rest are just
	 * discarded.
	 */
	list_for_each_entry(b, &local->services, local_link) {
		for (i = 0; i < b->ids->nr_ids; i++)
			if (b->ids->ids[i].service_id == sp->hdr.serviceId)
				goto found_service;
	}

	read_unlock(&local->services_lock);

unsupported_service:
	if (sp->hdr.type != RXRPC_PACKET_TYPE_DATA ||
	    sp->hdr.seq != 1)
		return true; /* Just discard */
	return rxrpc_direct_abort(skb, rxrpc_abort_service_not_offered,
				  RX_INVALID_OPERATION, -EOPNOTSUPP);

found_service:
	spin_lock(&b->incoming_lock);

	if (refcount_read(&b->active) == 0) {
		rxrpc_direct_abort(skb, rxrpc_abort_service_not_offered,
				   RX_INVALID_OPERATION, -ESHUTDOWN);
		goto no_call;
	}

	if (b->nr_tba >= b->max_tba) {
		skb->mark = RXRPC_SKB_MARK_REJECT_BUSY;
		goto no_call;
	}

	if (!conn) {
		sec = rxrpc_get_incoming_security(b, skb);
		if (!sec)
			goto unsupported_security;
	}

	if (!b->max_tba) {
		rxrpc_direct_abort(skb, rxrpc_abort_shut_down,
				   RX_INVALID_OPERATION, -ESHUTDOWN);
		goto no_call;
	}

	call = rxrpc_alloc_incoming_call(b, local, peer, conn, sec, peer_srx,
					 skb);
	if (!call) {
		skb->mark = RXRPC_SKB_MARK_REJECT_BUSY;
		goto no_call;
	}

	trace_rxrpc_receive(call, rxrpc_receive_incoming,
			    sp->hdr.serial, sp->hdr.seq);

	/* Make the call live. */
	rcu_assign_pointer(call->socket, b->kernel_sock);
	rxrpc_incoming_call(call, skb);
	conn = call->conn;

	if (b->notify_new_call)
		b->notify_new_call(b->kernel_sock, call, call->user_call_ID);
	spin_unlock(&b->incoming_lock);
	read_unlock(&local->services_lock);

	spin_lock(&conn->state_lock);
	if (conn->state == RXRPC_CONN_SERVICE_UNSECURED) {
		conn->state = RXRPC_CONN_SERVICE_CHALLENGING;
		set_bit(RXRPC_CONN_EV_CHALLENGE, &call->conn->events);
		rxrpc_queue_conn(call->conn, rxrpc_conn_queue_challenge);
	}
	spin_unlock(&conn->state_lock);

	if (hlist_unhashed(&call->error_link)) {
		spin_lock(&call->peer->lock);
		hlist_add_head(&call->error_link, &call->peer->error_targets);
		spin_unlock(&call->peer->lock);
	}

	_leave(" = %p{%d}", call, call->debug_id);
	rxrpc_input_call_event(call, skb);
	rxrpc_put_call(call, rxrpc_call_put_input);
	return true;

unsupported_security:
	spin_unlock(&b->incoming_lock);
	read_unlock(&local->services_lock);
	return rxrpc_direct_abort(skb, rxrpc_abort_service_not_offered,
				  RX_INVALID_OPERATION, -EKEYREJECTED);
no_call:
	spin_unlock(&b->incoming_lock);
	read_unlock(&local->services_lock);
	_leave(" = f [%u]", skb->mark);
	return false;
}

/*
 * Charge up socket with preallocated calls, attaching user call IDs.
 */
int rxrpc_user_charge_accept(struct rxrpc_sock *rx, unsigned long user_call_ID)
{
	int ret;

	if (rx->sk.sk_state == RXRPC_CLOSE)
		return -ESHUTDOWN;

	ret = rxrpc_service_preallocate(rx);
	if (ret < 0)
		return ret;

	return rxrpc_service_charge_user_call_id(rx, user_call_ID);
}

/**
 * rxrpc_kernel_charge_accept - Charge up socket with preallocated calls
 * @sock: The socket on which to preallocate
 *
 * Charge up the socket with preallocated calls.
 */
int rxrpc_kernel_charge_accept(struct socket *sock)
{
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);

	if (sock->sk->sk_state == RXRPC_CLOSE)
		return -ESHUTDOWN;

	return rxrpc_service_preallocate(rx);
}
EXPORT_SYMBOL(rxrpc_kernel_charge_accept);
