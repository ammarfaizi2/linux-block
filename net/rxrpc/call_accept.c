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
void rxrpc_service_preallocate(struct work_struct *work)
{
	struct rxrpc_service *b = container_of(work, struct rxrpc_service, preallocator);
	struct rxrpc_local *local = b->local;
	struct rxrpc_net *rxnet = local->rxnet;
	unsigned int head, tail, size = RXRPC_BACKLOG_MAX;
	int max = b->max_tba;

	if (!refcount_read(&b->active))
		return;

	head = b->peer_backlog_head;
	tail = READ_ONCE(b->peer_backlog_tail);
	while (CIRC_CNT(head, tail, size) < max) {
		struct rxrpc_peer *peer = rxrpc_alloc_peer(local, GFP_KERNEL);
		if (!peer)
			goto nomem;
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
			goto nomem;

		trace_rxrpc_conn(conn->debug_id, rxrpc_conn_new_service,
				 refcount_read(&conn->ref), NULL);

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

		call = rxrpc_alloc_call(b->local, GFP_KERNEL, debug_id, b);
		if (!call)
			goto nomem;
		call->flags |= (1 << RXRPC_CALL_IS_SERVICE);
		call->state = RXRPC_CALL_SERVER_PREALLOC;
		call->notify_rx = b->notify_rx;
		__set_bit(RXRPC_CALL_NEWLY_ACCEPTED, &call->flags);

		if (b->kernel_sock) {
			struct rxrpc_sock *rx = rxrpc_sk(b->kernel_sock);

			rcu_assign_pointer(call->socket, b->kernel_sock);
			rxrpc_get_call(call, rxrpc_call_get_socket_list);
			write_lock(&rx->call_lock);
			list_add(&call->sock_link, &rx->sock_calls);
			write_unlock(&rx->call_lock);
		} else {
			refcount_inc(&b->ref);
			call->service = b;
		}

		spin_lock_bh(&rxnet->call_lock);
		list_add_tail_rcu(&call->link, &rxnet->calls);
		spin_unlock_bh(&rxnet->call_lock);

		trace_rxrpc_call(call->debug_id, rxrpc_call_new_service,
				 refcount_read(&call->ref), NULL,
				 (void *)(unsigned long)head);

		b->call_backlog[head++] = call;
		head &= size - 1;
		smp_store_release(&b->call_backlog_head, head);
	}

	return;

nomem:
	WRITE_ONCE(b->error, -ENOMEM);
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

	if (list_empty(&rx->accepting_link)) {
		spin_lock_bh(&b->incoming_lock);
		if (list_empty(&rx->accepting_link))
			list_add_tail(&rx->accepting_link, &b->waiting_sockets);
		spin_unlock_bh(&b->incoming_lock);
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
void rxrpc_accept_incoming_call(struct rxrpc_sock *rx)
{
	struct rxrpc_service *b = rx->service;
	struct rxrpc_call *xcall, *call;
	struct rb_node *parent, **pp;
	const void *here = __builtin_return_address(0);
	unsigned int head, tail, size = RXRPC_BACKLOG_MAX;

	if (CIRC_CNT(rx->call_id_backlog_head, rx->call_id_backlog_tail, size) == 0)
		return;

	write_lock(&rx->call_lock);

	/* Obtain an ID from the preallocation ring. */
	head = smp_load_acquire(&rx->call_id_backlog_head);
	tail = rx->call_id_backlog_tail;

	if (CIRC_CNT(head, tail, size) == 0) {
		write_unlock(&rx->call_lock);
		return;
	}

	spin_lock_bh(&b->incoming_lock);

	call = list_first_entry_or_null(&b->to_be_accepted,
					struct rxrpc_call, recvmsg_link);
	if (!call) {
		spin_unlock_bh(&b->incoming_lock);
		write_unlock(&rx->call_lock);
		return;
	}

	write_lock(&rx->recvmsg_lock);
	rxrpc_get_call(call, rxrpc_call_got_userid);
	call->user_call_ID = rx->call_id_backlog[tail];
	rcu_assign_pointer(call->socket, rx);
	/* recvmsg_link mustn't be seen to be empty. */
	list_move_tail(&call->recvmsg_link, &rx->recvmsg_q);
	b->nr_tba--;
	write_unlock(&rx->recvmsg_lock);

	rx->call_id_backlog[tail] = 0;
	tail = (tail + 1) & (size - 1);
	smp_store_release(&rx->call_id_backlog_tail, tail);

	if (CIRC_CNT(head, tail, size) == 0)
		list_del_init(&rx->accepting_link);

	spin_unlock_bh(&b->incoming_lock);

	trace_rxrpc_call(call->debug_id, rxrpc_call_accepted,
			 refcount_read(&call->ref),
			 here, (const void *)call->user_call_ID);

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

	rxrpc_get_call(call, rxrpc_call_get_socket_list);
	list_add(&call->sock_link, &rx->sock_calls);
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

	spin_lock_bh(&b->incoming_lock);
	list_del_init(&rx->accepting_link);
	spin_unlock_bh(&b->incoming_lock);

	if (!refcount_dec_and_test(&rx->service->active))
		return;

	/* Now that active is 0, make sure that there aren't any incoming calls
	 * being set up before we clear the preallocation buffers.
	 */
	spin_lock_bh(&b->incoming_lock);
	spin_unlock_bh(&b->incoming_lock);

	mutex_lock(&rx->local->services_lock);
	list_del_rcu(&b->local_link);
	mutex_unlock(&rx->local->services_lock);

	cancel_work_sync(&b->preallocator);

	head = b->peer_backlog_head;
	tail = b->peer_backlog_tail;
	while (CIRC_CNT(head, tail, size) > 0) {
		struct rxrpc_peer *peer = b->peer_backlog[tail];
		rxrpc_put_local(peer->local);
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

		trace_rxrpc_call(call->debug_id, rxrpc_call_discard,
				 refcount_read(&call->ref),
				 NULL, (const void *)call->user_call_ID);
		if (b->discard_new_call) {
			_debug("discard %lx", call->user_call_ID);
			b->discard_new_call(call, call->user_call_ID);
			if (call->notify_rx)
				call->notify_rx = rxrpc_dummy_notify;
			rxrpc_put_call(call, rxrpc_call_put_kernel);
		}

		rxrpc_call_completed(call);
		rxrpc_release_call(call);
		rxrpc_put_call(call, rxrpc_call_put);
		tail = (tail + 1) & (size - 1);
	}

	spin_lock_bh(&b->incoming_lock);
	while (!list_empty(&b->to_be_accepted)) {
		struct rxrpc_call *call =
			list_entry(b->to_be_accepted.next,
				   struct rxrpc_call, recvmsg_link);
		spin_unlock_bh(&b->incoming_lock);
		if (rxrpc_abort_call("SKR", call, 0, RX_CALL_DEAD, -ECONNRESET))
			rxrpc_send_abort_packet(call);
		rxrpc_release_call(call);
		rxrpc_put_call(call, rxrpc_call_put);
		spin_lock_bh(&b->incoming_lock);
	}
	spin_unlock_bh(&b->incoming_lock);

}

/*
 * Ping the other end to fill our RTT cache and to retrieve the rwind
 * and MTU parameters.
 */
static void rxrpc_send_ping(struct rxrpc_call *call, struct sk_buff *skb)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	ktime_t now = skb->tstamp;

	if (call->peer->rtt_count < 3 ||
	    ktime_before(ktime_add_ms(call->peer->rtt_last_req, 1000), now))
		rxrpc_propose_ACK(call, RXRPC_ACK_PING, sp->hdr.serial,
				  true, true,
				  rxrpc_propose_ack_ping_for_params);
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
						    struct sk_buff *skb)
{
	struct rxrpc_call *call;
	unsigned short call_head, conn_head, peer_head;
	unsigned short call_tail, conn_tail, peer_tail;
	unsigned short call_count, conn_count, peer_count;

	call_head = smp_load_acquire(&b->call_backlog_head);
	call_tail = b->call_backlog_tail;
	call_count = CIRC_CNT(call_head, call_tail, RXRPC_BACKLOG_MAX);
	conn_head = smp_load_acquire(&b->conn_backlog_head);
	conn_tail = b->conn_backlog_tail;
	conn_count = CIRC_CNT(conn_head, conn_tail, RXRPC_BACKLOG_MAX);
	peer_head = smp_load_acquire(&b->peer_backlog_head);
	peer_tail = b->peer_backlog_tail;
	peer_count = CIRC_CNT(peer_head, peer_tail, RXRPC_BACKLOG_MAX);

	if (call_count == 0)
		return NULL;

	if (!conn) {
		if (conn_count == 0 || peer_count == 0)
			return NULL;
		if (peer && !rxrpc_get_peer_maybe(peer))
			peer = NULL;
		if (!peer) {
			peer = b->peer_backlog[peer_tail];
			if (rxrpc_extract_addr_from_skb(&peer->srx, skb) < 0)
				return NULL;
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
		conn->params.local = rxrpc_get_local(local);
		conn->params.peer = peer;
		rxrpc_see_connection(conn);
		rxrpc_new_incoming_connection(b, conn, sec, skb);
	} else {
		rxrpc_get_connection(conn);
	}

	/* And now we can allocate and set up a new call */
	call = b->call_backlog[call_tail];
	b->call_backlog[call_tail] = NULL;
	smp_store_release(&b->call_backlog_tail,
			  (call_tail + 1) & (RXRPC_BACKLOG_MAX - 1));

	rxrpc_see_call(call);
	call->conn = conn;
	call->security = conn->security;
	call->security_ix = conn->security_ix;
	call->peer = rxrpc_get_peer(conn->params.peer);
	call->cong_cwnd = call->peer->cong_cwnd;
	__set_bit(RXRPC_CALL_RX_HEARD, &call->flags);
	return call;
}

/*
 * Set up a new incoming call.  Called in BH context with the RCU read lock
 * held.
 *
 * If this is for a kernel service, when we allocate the call, it will have
 * three refs on it: (1) the kernel service, (2) the user_call_ID tree, (3) the
 * retainer ref obtained from the backlog buffer.  Prealloc calls for userspace
 * services only have the ref from the backlog buffer.  We want to pass this
 * ref to non-BH context to dispose of.
 *
 * If we want to report an error, we mark the skb with the packet type and
 * abort code and return NULL.
 *
 * The call is returned with the user access mutex held.
 */
struct rxrpc_call *rxrpc_new_incoming_call(struct rxrpc_local *local,
					   struct sk_buff *skb)
{
	struct rxrpc_skb_priv *sp = rxrpc_skb(skb);
	const struct rxrpc_service_ids *ids;
	const struct rxrpc_security *sec = NULL;
	struct rxrpc_connection *conn;
	struct rxrpc_service *b;
	struct rxrpc_peer *peer = NULL;
	struct rxrpc_call *call = NULL;
	unsigned int i;

	_enter("");

	list_for_each_entry_rcu(b, &local->services, local_link) {
		ids = rcu_dereference(b->ids);
		for (i = 0; i < ids->nr_ids; i++)
			if (ids->ids[i].service_id == sp->hdr.serviceId)
				goto found_service;
	}
	_leave(" = NULL [no srv]");
	return NULL;

found_service:
	spin_lock(&b->incoming_lock);

	if (refcount_read(&b->active) == 0) {
		trace_rxrpc_abort(0, "CLS", sp->hdr.cid, sp->hdr.callNumber,
				  sp->hdr.seq, RX_INVALID_OPERATION, ESHUTDOWN);
		skb->mark = RXRPC_SKB_MARK_REJECT_ABORT;
		skb->priority = RX_INVALID_OPERATION;
		goto no_call;
	}

	if (b->nr_tba >= b->max_tba) {
		skb->mark = RXRPC_SKB_MARK_REJECT_BUSY;
		goto no_call;
	}

	/* The peer, connection and call may all have sprung into existence due
	 * to a duplicate packet being handled on another CPU in parallel, so
	 * we have to recheck the routing.  However, we're now holding
	 * incoming_lock, so the values should remain stable.
	 */
	conn = rxrpc_find_connection_rcu(local, skb, &peer);

	if (!conn) {
		sec = rxrpc_get_incoming_security(b, skb);
		if (!sec)
			goto no_call;
	}

	call = rxrpc_alloc_incoming_call(b, local, peer, conn, sec, skb);
	if (!call) {
		skb->mark = RXRPC_SKB_MARK_REJECT_BUSY;
		goto no_call;
	}

	trace_rxrpc_receive(call, rxrpc_receive_incoming,
			    sp->hdr.serial, sp->hdr.seq);

	/* Make the call live. */
	if (!rcu_access_pointer(call->socket))
		rcu_assign_pointer(call->socket, b->kernel_sock);
	rxrpc_incoming_call(call, skb);
	trace_rxrpc_accept_call(call);
	conn = call->conn;

	if (b->notify_new_call)
		b->notify_new_call(b->kernel_sock, call, call->user_call_ID);
	spin_unlock(&b->incoming_lock);
	schedule_work(&b->preallocator);

	spin_lock(&conn->state_lock);
	switch (conn->state) {
	case RXRPC_CONN_SERVICE_UNSECURED:
		conn->state = RXRPC_CONN_SERVICE_CHALLENGING;
		set_bit(RXRPC_CONN_EV_CHALLENGE, &call->conn->events);
		rxrpc_queue_conn(call->conn);
		break;

	case RXRPC_CONN_SERVICE:
		write_lock(&call->state_lock);
		if (call->state < RXRPC_CALL_COMPLETE)
			call->state = RXRPC_CALL_SERVER_RECV_REQUEST;
		write_unlock(&call->state_lock);
		break;

	case RXRPC_CONN_REMOTELY_ABORTED:
		rxrpc_set_call_completion(call, RXRPC_CALL_REMOTELY_ABORTED,
					  conn->abort_code, conn->error);
		break;
	case RXRPC_CONN_LOCALLY_ABORTED:
		rxrpc_abort_call("CON", call, sp->hdr.seq,
				 conn->abort_code, conn->error);
		break;
	default:
		BUG();
	}
	spin_unlock(&conn->state_lock);

	rxrpc_send_ping(call, skb);

	/* We have to discard the prealloc queue's ref here and rely on a
	 * combination of the RCU read lock and refs held either by the socket
	 * (recvmsg queue, to-be-accepted queue or user ID tree) or the kernel
	 * service to prevent the call from being deallocated too early.
	 */
	//rxrpc_put_call(call, rxrpc_call_put);

	_leave(" = %p{%d}", call, call->debug_id);
	return call;

no_call:
	spin_unlock(&b->incoming_lock);
	_leave(" = NULL [%u]", skb->mark);
	return NULL;
}

/*
 * Charge up socket with preallocated calls, attaching user call IDs.
 */
int rxrpc_user_charge_accept(struct rxrpc_sock *rx, unsigned long user_call_ID)
{
	int ret;

	if (rx->sk.sk_state == RXRPC_CLOSE)
		return -ESHUTDOWN;

	ret = xchg(&rx->service->error, 0);
	if (ret < 0)
		return ret;

	return rxrpc_service_charge_user_call_id(rx, user_call_ID);
}
