// SPDX-License-Identifier: GPL-2.0-or-later
/* AF_RXRPC implementation
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/circ_buf.h>
#include <linux/key-type.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#define CREATE_TRACE_POINTS
#include "ar-internal.h"

MODULE_DESCRIPTION("RxRPC network protocol");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_RXRPC);

unsigned int rxrpc_debug; // = RXRPC_DEBUG_KPROTO;
module_param_named(debug, rxrpc_debug, uint, 0644);
MODULE_PARM_DESC(debug, "RxRPC debugging mask");

static struct proto rxrpc_proto;
static const struct proto_ops rxrpc_rpc_ops;

/* current debugging ID */
atomic_t rxrpc_debug_id;
EXPORT_SYMBOL(rxrpc_debug_id);

/* count of skbs currently in use */
atomic_t rxrpc_n_tx_skbs, rxrpc_n_rx_skbs;

struct workqueue_struct *rxrpc_workqueue;

static void rxrpc_sock_destructor(struct sock *);

/*
 * see if an RxRPC socket is currently writable
 */
static inline int rxrpc_writable(struct sock *sk)
{
	return refcount_read(&sk->sk_wmem_alloc) < (size_t) sk->sk_sndbuf;
}

/*
 * wait for write bufferage to become available
 */
static void rxrpc_write_space(struct sock *sk)
{
	_enter("%p", sk);
	rcu_read_lock();
	if (rxrpc_writable(sk)) {
		struct socket_wq *wq = rcu_dereference(sk->sk_wq);

		if (skwq_has_sleeper(wq))
			wake_up_interruptible(&wq->wait);
		sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
	}
	rcu_read_unlock();
}

/*
 * validate an RxRPC address
 */
static int rxrpc_validate_address(struct rxrpc_sock *rx,
				  struct sockaddr_rxrpc *srx,
				  int len)
{
	unsigned int tail;

	if (len < sizeof(struct sockaddr_rxrpc))
		return -EINVAL;

	if (srx->srx_family != AF_RXRPC)
		return -EAFNOSUPPORT;

	if (srx->transport_type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	len -= offsetof(struct sockaddr_rxrpc, transport);
	if (srx->transport_len < sizeof(sa_family_t) ||
	    srx->transport_len > len)
		return -EINVAL;

	if (srx->transport.family != rx->family &&
	    srx->transport.family == AF_INET && rx->family != AF_INET6)
		return -EAFNOSUPPORT;

	switch (srx->transport.family) {
	case AF_INET:
		if (srx->transport_len < sizeof(struct sockaddr_in))
			return -EINVAL;
		tail = offsetof(struct sockaddr_rxrpc, transport.sin.__pad);
		break;

#ifdef CONFIG_AF_RXRPC_IPV6
	case AF_INET6:
		if (srx->transport_len < sizeof(struct sockaddr_in6))
			return -EINVAL;
		tail = offsetof(struct sockaddr_rxrpc, transport) +
			sizeof(struct sockaddr_in6);
		break;
#endif

	default:
		return -EAFNOSUPPORT;
	}

	if (tail < len)
		memset((void *)srx + tail, 0, len - tail);
	_debug("INET: %pISp", &srx->transport);
	return 0;
}

/*
 * Bind a service to an rxrpc socket.
 */
static int rxrpc_bind_service(struct rxrpc_sock *rx, struct rxrpc_local *local,
			      u16 service_id)
{
	struct rxrpc_service_ids *ids;
	struct rxrpc_service *b;
	int i;

	list_for_each_entry(b, &local->services, local_link) {
		ids = rcu_dereference_protected(
			b->ids, lockdep_is_held(&rx->local->services_lock));
		for (i = 0; i < ids->nr_ids; i++)
			if (service_id == ids->ids[i].service_id)
				return -EADDRINUSE;
	}

	b = kzalloc(sizeof(struct rxrpc_service), GFP_KERNEL);
	if (!b)
		return -ENOMEM;
	INIT_LIST_HEAD(&b->local_link);
	INIT_LIST_HEAD(&b->to_be_accepted);
	INIT_LIST_HEAD(&b->waiting_sockets);
	INIT_WORK(&b->preallocator, rxrpc_service_preallocate);
	spin_lock_init(&b->incoming_lock);
	refcount_set(&b->ref, 1);
	refcount_set(&b->active, 1);
	b->local = local;

	ids = kzalloc(struct_size(ids, ids, 1), GFP_KERNEL);
	if (!ids) {
		kfree(b);
		return -ENOMEM;
	}

	ids->nr_ids = 1;
	ids->ids[0].service_id = service_id;
	rcu_assign_pointer(b->ids, ids);

	rx->service = b;
	rx->local = local;
	list_add_tail_rcu(&b->local_link, &local->services);
	return 0;
}

/*
 * Bind an additional service to an rxrpc socket.
 */
static int rxrpc_bind_service2(struct rxrpc_sock *rx, struct rxrpc_local *local,
			       u16 service_id)
{
	struct rxrpc_service_ids *ids, *old;
	struct rxrpc_service *b;
	int i;

	list_for_each_entry(b, &local->services, local_link) {
		ids = rcu_dereference_protected(
			b->ids, lockdep_is_held(&rx->local->services_lock));
		for (i = 0; i < ids->nr_ids; i++)
			if (service_id == ids->ids[i].service_id)
				return -EADDRINUSE;
	}

	b = rx->service;
	old = rcu_dereference_protected(
		b->ids, lockdep_is_held(&local->services_lock));

	ids = kzalloc(struct_size(ids, ids, old->nr_ids + 1), GFP_KERNEL);
	if (!ids)
		return -ENOMEM;

	memcpy(ids, old, struct_size(ids, ids, old->nr_ids));
	ids->ids[ids->nr_ids++].service_id = service_id;
	rcu_assign_pointer(b->ids, ids);
	kfree_rcu(old, rcu);
	return 0;
}

/*
 * Mark a service on an rxrpc socket as upgradable.  Both service IDs must have
 * been bound to this socket and upgrade-to-same is not allowed.
 */
static int rxrpc_bind_service_upgrade(struct rxrpc_sock *rx,
				      u16 service_id, u16 upgrade_to)
{
	struct rxrpc_service_ids *ids;
	struct rxrpc_service *b = rx->service;
	int i;

	if (upgrade_to == service_id)
		return -EINVAL;

	ids = rcu_dereference_protected(
		b->ids, lockdep_is_held(&rx->local->services_lock));
	for (i = 0; i < ids->nr_ids; i++)
		if (upgrade_to == ids->ids[i].service_id)
			goto found_upgrade;
	return -EINVAL;

found_upgrade:
	for (i = 0; i < ids->nr_ids; i++) {
		if (service_id == ids->ids[i].service_id) {
			if (ids->ids[i].upgrade_to)
				return -EINVAL;
			ids->ids[i].upgrade_to = upgrade_to;
		}
	}
	return 0;
}

/*
 * bind a local address to an RxRPC socket
 */
static int rxrpc_bind(struct socket *sock, struct sockaddr *saddr, int len)
{
	struct sockaddr_rxrpc *srx = (struct sockaddr_rxrpc *)saddr;
	struct rxrpc_local *local;
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	u16 service_id;
	int ret;

	_enter("%p,%p,%d", rx, saddr, len);

	ret = rxrpc_validate_address(rx, srx, len);
	if (ret < 0)
		goto error;
	service_id = srx->srx_service;

	lock_sock(&rx->sk);

	switch (rx->sk.sk_state) {
	case RXRPC_UNBOUND:
		local = rxrpc_lookup_local(sock_net(&rx->sk), srx,
					   rx->sk.sk_kern_sock);
		if (IS_ERR(local)) {
			ret = PTR_ERR(local);
			goto error_unlock;
		}

		if (service_id) {
			mutex_lock(&local->services_lock);
			ret = rxrpc_bind_service(rx, local, service_id);
			if (ret)
				goto service_in_use;
			mutex_unlock(&local->services_lock);

			srx->srx_service = 0;
			rx->srx = *srx;
			rx->sk.sk_state = RXRPC_SERVER_BOUND;
		} else {
			srx->srx_service = 0;
			rx->srx = *srx;
			rx->local = local;
			rx->sk.sk_state = RXRPC_CLIENT_BOUND;
		}
		break;

	case RXRPC_SERVER_BOUND:
		local = rx->local;
		ret = -EINVAL;
		if (service_id == 0)
			goto error_unlock;
		srx->srx_service = 0;
		if (memcmp(srx, &rx->srx, sizeof(*srx)) != 0)
			goto error_unlock;

		mutex_lock(&local->services_lock);
		ret = rxrpc_bind_service2(rx, local, service_id);
		if (ret)
			goto service_in_use;
		mutex_unlock(&local->services_lock);
		break;

	default:
		ret = -EINVAL;
		goto error_unlock;
	}

	release_sock(&rx->sk);
	_leave(" = 0");
	return 0;

service_in_use:
	mutex_unlock(&local->services_lock);
	rxrpc_unuse_local(local);
	rxrpc_put_local(local);
	ret = -EADDRINUSE;
error_unlock:
	release_sock(&rx->sk);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * set the number of pending calls permitted on a listening socket
 */
static int rxrpc_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct rxrpc_service *b;
	struct rxrpc_sock *rx = rxrpc_sk(sk);
	unsigned int max;
	int ret;

	_enter("%p,%d", rx, backlog);

	lock_sock(&rx->sk);
	b = rx->service;

	switch (rx->sk.sk_state) {
	case RXRPC_UNBOUND:
		ret = -EADDRNOTAVAIL;
		break;
	case RXRPC_SERVER_BOUND:
		ASSERT(rx->local != NULL);
		max = READ_ONCE(rxrpc_max_backlog);
		ret = -EINVAL;
		if (backlog == INT_MAX)
			backlog = max;
		else if (backlog < 0 || backlog > max)
			break;
		ret = -ENOMEM;
		if (!rx->sk.sk_kern_sock) {
			rx->call_id_backlog =
				kcalloc(RXRPC_BACKLOG_MAX,
					sizeof(rx->call_id_backlog[0]),
					GFP_KERNEL);
			if (!rx->call_id_backlog)
				break;
		}
		b->max_tba = backlog;
		rx->sk.sk_state = RXRPC_SERVER_LISTENING;
		schedule_work(&b->preallocator);
		ret = 0;
		break;
	case RXRPC_SERVER_LISTENING:
		if (backlog == 0) {
			rx->sk.sk_state = RXRPC_SERVER_LISTEN_DISABLED;
			b->max_tba = 0;
			ret = 0;
			break;
		}
		fallthrough;
	default:
		ret = -EBUSY;
		break;
	}

	release_sock(&rx->sk);
	_leave(" = %d", ret);
	return ret;
}

/**
 * rxrpc_kernel_begin_call - Allow a kernel service to begin a call
 * @sock: The socket on which to make the call
 * @srx: The address of the peer to contact
 * @key: The security context to use (defaults to socket setting)
 * @user_call_ID: The ID to use
 * @tx_total_len: Total length of data to transmit during the call (or -1)
 * @gfp: The allocation constraints
 * @notify_rx: Where to send notifications instead of socket queue
 * @upgrade: Request service upgrade for call
 * @interruptibility: The call is interruptible, or can be canceled.
 * @debug_id: The debug ID for tracing to be assigned to the call
 *
 * Allow a kernel service to begin a call on the nominated socket.  This just
 * sets up all the internal tracking structures and allocates connection and
 * call IDs as appropriate.  The call to be used is returned.
 *
 * The default socket destination address and security may be overridden by
 * supplying @srx and @key.
 */
struct rxrpc_call *rxrpc_kernel_begin_call(struct socket *sock,
					   struct sockaddr_rxrpc *srx,
					   struct key *key,
					   unsigned long user_call_ID,
					   s64 tx_total_len,
					   gfp_t gfp,
					   rxrpc_notify_rx_t notify_rx,
					   bool upgrade,
					   enum rxrpc_interruptibility interruptibility,
					   unsigned int debug_id)
{
	struct rxrpc_conn_parameters cp;
	struct rxrpc_call_params p;
	struct rxrpc_call *call;
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	int ret;

	_enter(",,%x,%lx", key_serial(key), user_call_ID);

	ret = rxrpc_validate_address(rx, srx, sizeof(*srx));
	if (ret < 0)
		return ERR_PTR(ret);

	lock_sock(&rx->sk);

	if (!key)
		key = rx->key;
	if (key && !key->payload.data[0])
		key = NULL; /* a no-security key */

	memset(&p, 0, sizeof(p));
	p.user_call_ID		= user_call_ID;
	p.tx_total_len		= tx_total_len;
	p.interruptibility	= interruptibility;
	p.kernel		= true;

	memset(&cp, 0, sizeof(cp));
	cp.local		= rx->local;
	cp.key			= key;
	cp.security_level	= rx->min_sec_level;
	cp.exclusive		= false;
	cp.upgrade		= upgrade;
	cp.service_id		= srx->srx_service;
	call = rxrpc_new_client_call(rx, &cp, srx, &p, gfp, debug_id);
	/* The socket has been unlocked. */
	if (!IS_ERR(call)) {
		call->notify_rx = notify_rx;
		mutex_unlock(&call->user_mutex);
	}

	rxrpc_put_peer(cp.peer);
	_leave(" = %p", call);
	return call;
}
EXPORT_SYMBOL(rxrpc_kernel_begin_call);

/*
 * Dummy function used to stop the notifier talking to recvmsg().
 */
static void rxrpc_dummy_notify_rx(struct sock *sk, struct rxrpc_call *rxcall,
				  unsigned long call_user_ID)
{
}

/**
 * rxrpc_kernel_end_call - Allow a kernel service to end a call it was using
 * @sock: The socket the call is on
 * @call: The call to end
 *
 * Allow a kernel service to end a call it was using.  The call must be
 * complete before this is called (the call should be aborted if necessary).
 */
void rxrpc_kernel_end_call(struct socket *sock, struct rxrpc_call *call)
{
	_enter("%d{%d}", call->debug_id, refcount_read(&call->ref));

	mutex_lock(&call->user_mutex);
	rxrpc_release_call(call);

	/* Make sure we're not going to call back into a kernel service */
	if (call->notify_rx) {
		spin_lock_bh(&call->notify_lock);
		call->notify_rx = rxrpc_dummy_notify_rx;
		spin_unlock_bh(&call->notify_lock);
	}

	mutex_unlock(&call->user_mutex);
	rxrpc_put_call(call, rxrpc_call_put_kernel);
}
EXPORT_SYMBOL(rxrpc_kernel_end_call);

/**
 * rxrpc_kernel_check_life - Check to see whether a call is still alive
 * @sock: The socket the call is on
 * @call: The call to check
 *
 * Allow a kernel service to find out whether a call is still alive -
 * ie. whether it has completed.
 */
bool rxrpc_kernel_check_life(const struct socket *sock,
			     const struct rxrpc_call *call)
{
	return call->state != RXRPC_CALL_COMPLETE;
}
EXPORT_SYMBOL(rxrpc_kernel_check_life);

/**
 * rxrpc_kernel_get_epoch - Retrieve the epoch value from a call.
 * @sock: The socket the call is on
 * @call: The call to query
 *
 * Allow a kernel service to retrieve the epoch value from a service call to
 * see if the client at the other end rebooted.
 */
u32 rxrpc_kernel_get_epoch(struct socket *sock, struct rxrpc_call *call)
{
	return call->conn->proto.epoch;
}
EXPORT_SYMBOL(rxrpc_kernel_get_epoch);

/**
 * rxrpc_kernel_new_call_notification - Get notifications of new calls
 * @sock: The socket to intercept received messages on
 * @notify_rx: Event notification function for the call
 * @preallocate_call: Func to obtain a user_call_ID
 * @notify_new_call: Function to be called when new calls appear
 * @discard_new_call: Function to discard preallocated calls
 *
 * Allow a kernel service to be given notifications about new calls.
 */
void rxrpc_kernel_new_call_notification(
	struct socket *sock,
	rxrpc_notify_rx_t notify_rx,
	rxrpc_preallocate_call_t preallocate_call,
	rxrpc_notify_new_call_t notify_new_call,
	rxrpc_discard_new_call_t discard_new_call)
{
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	struct rxrpc_service *b = rx->service;

	b->kernel_sock = sock->sk;
	b->notify_rx = notify_rx;
	b->preallocate_call = preallocate_call;
	b->notify_new_call = notify_new_call;
	b->discard_new_call = discard_new_call;
}
EXPORT_SYMBOL(rxrpc_kernel_new_call_notification);

/**
 * rxrpc_kernel_set_max_life - Set maximum lifespan on a call
 * @sock: The socket the call is on
 * @call: The call to configure
 * @hard_timeout: The maximum lifespan of the call in jiffies
 *
 * Set the maximum lifespan of a call.  The call will end with ETIME or
 * ETIMEDOUT if it takes longer than this.
 */
void rxrpc_kernel_set_max_life(struct socket *sock, struct rxrpc_call *call,
			       unsigned long hard_timeout)
{
	unsigned long now;

	mutex_lock(&call->user_mutex);

	now = jiffies;
	hard_timeout += now;
	WRITE_ONCE(call->expect_term_by, hard_timeout);
	rxrpc_reduce_call_timer(call, hard_timeout, now, rxrpc_timer_set_for_hard);

	mutex_unlock(&call->user_mutex);
}
EXPORT_SYMBOL(rxrpc_kernel_set_max_life);

/*
 * connect an RxRPC socket
 * - this just targets it at a specific destination; no actual connection
 *   negotiation takes place
 */
static int rxrpc_connect(struct socket *sock, struct sockaddr *addr,
			 int addr_len, int flags)
{
	struct sockaddr_rxrpc *srx = (struct sockaddr_rxrpc *)addr;
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	int ret;

	_enter("%p,%p,%d,%d", rx, addr, addr_len, flags);

	ret = rxrpc_validate_address(rx, srx, addr_len);
	if (ret < 0) {
		_leave(" = %d [bad addr]", ret);
		return ret;
	}

	lock_sock(&rx->sk);

	ret = -EISCONN;
	if (test_bit(RXRPC_SOCK_CONNECTED, &rx->flags))
		goto error;

	switch (rx->sk.sk_state) {
	case RXRPC_UNBOUND:
		rx->sk.sk_state = RXRPC_CLIENT_UNBOUND;
		break;
	case RXRPC_CLIENT_UNBOUND:
	case RXRPC_CLIENT_BOUND:
		break;
	default:
		ret = -EBUSY;
		goto error;
	}

	rx->connect_srx = *srx;
	set_bit(RXRPC_SOCK_CONNECTED, &rx->flags);
	ret = 0;

error:
	release_sock(&rx->sk);
	return ret;
}

/*
 * send a message through an RxRPC socket
 * - in a client this does a number of things:
 *   - finds/sets up a connection for the security specified (if any)
 *   - initiates a call (ID in control data)
 *   - ends the request phase of a call (if MSG_MORE is not set)
 *   - sends a call data packet
 *   - may send an abort (abort code in control data)
 */
static int rxrpc_sendmsg(struct socket *sock, struct msghdr *m, size_t len)
{
	struct rxrpc_local *local;
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	int ret;

	_enter(",{%d},,%zu", rx->sk.sk_state, len);

	if (m->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	if (m->msg_name) {
		ret = rxrpc_validate_address(rx, m->msg_name, m->msg_namelen);
		if (ret < 0) {
			_leave(" = %d [bad addr]", ret);
			return ret;
		}
	}

	lock_sock(&rx->sk);

	switch (rx->sk.sk_state) {
	case RXRPC_UNBOUND:
	case RXRPC_CLIENT_UNBOUND:
		rx->srx.srx_family = AF_RXRPC;
		rx->srx.srx_service = 0;
		rx->srx.transport_type = SOCK_DGRAM;
		rx->srx.transport.family = rx->family;
		switch (rx->family) {
		case AF_INET:
			rx->srx.transport_len = sizeof(struct sockaddr_in);
			break;
#ifdef CONFIG_AF_RXRPC_IPV6
		case AF_INET6:
			rx->srx.transport_len = sizeof(struct sockaddr_in6);
			break;
#endif
		default:
			ret = -EAFNOSUPPORT;
			goto error_unlock;
		}
		local = rxrpc_lookup_local(sock_net(sock->sk), &rx->srx,
					   rx->sk.sk_kern_sock);
		if (IS_ERR(local)) {
			ret = PTR_ERR(local);
			goto error_unlock;
		}

		rx->local = local;
		rx->sk.sk_state = RXRPC_CLIENT_BOUND;
		fallthrough;

	case RXRPC_CLIENT_BOUND:
		if (!m->msg_name &&
		    test_bit(RXRPC_SOCK_CONNECTED, &rx->flags)) {
			m->msg_name = &rx->connect_srx;
			m->msg_namelen = sizeof(rx->connect_srx);
		}
		fallthrough;
	case RXRPC_SERVER_BOUND:
	case RXRPC_SERVER_LISTENING:
		ret = rxrpc_do_sendmsg(rx, m, len);
		/* The socket has been unlocked */
		goto out;
	default:
		ret = -EINVAL;
		goto error_unlock;
	}

error_unlock:
	release_sock(&rx->sk);
out:
	_leave(" = %d", ret);
	return ret;
}

int rxrpc_sock_set_min_security_level(struct sock *sk, unsigned int val)
{
	if (sk->sk_state != RXRPC_UNBOUND)
		return -EISCONN;
	if (val > RXRPC_SECURITY_MAX)
		return -EINVAL;
	lock_sock(sk);
	rxrpc_sk(sk)->min_sec_level = val;
	release_sock(sk);
	return 0;
}
EXPORT_SYMBOL(rxrpc_sock_set_min_security_level);

int rxrpc_sock_set_upgradeable_service(struct sock *sk, unsigned int val[2])
{
	struct rxrpc_sock *rx = rxrpc_sk(sk);
	int ret = -EISCONN;

	lock_sock(sk);
	if (rx->sk.sk_state == RXRPC_SERVER_BOUND) {
		mutex_lock(&rx->local->services_lock);
		ret = rxrpc_bind_service_upgrade(rx, val[0], val[1]);
		mutex_unlock(&rx->local->services_lock);
	}
	release_sock(sk);
	return ret;
}
EXPORT_SYMBOL(rxrpc_sock_set_upgradeable_service);

/*
 * Bind this socket to another socket that's already set up and listening to
 * use this as an additional channel for receiving new service calls.
 */
static int rxrpc_bind_channel(struct rxrpc_sock *rx2, int fd)
{
	struct rxrpc_service *b;
	struct rxrpc_sock *rx1;
	struct socket *sock1;
	unsigned long *call_id_backlog;
	int ret;

	if (rx2->sk.sk_state != RXRPC_UNBOUND)
		return -EISCONN;
	if (rx2->service || rx2->exclusive)
		return -EINVAL;

	sock1 = sockfd_lookup(fd, &ret);
	if (!sock1)
		return ret;
	rx1 = rxrpc_sk(sock1->sk);

	ret = -EINVAL;
	if (rx1 == rx2 || rx2->family != rx1->family ||
	    sock_net(&rx2->sk) != sock_net(&rx1->sk))
		goto error;

	ret = -EISCONN;
	if (rx1->sk.sk_state != RXRPC_SERVER_LISTENING)
		goto error;

	ret = -ENOMEM;
	call_id_backlog = kcalloc(RXRPC_BACKLOG_MAX,
				  sizeof(call_id_backlog[0]),
				  GFP_KERNEL);
	if (!call_id_backlog)
		goto error;

	lock_sock_nested(&rx1->sk, 1);

	ret = -EISCONN;
	if (rx1->sk.sk_state != RXRPC_SERVER_LISTENING)
		goto error_unlock;

	b = rx1->service;
	refcount_inc(&b->ref);
	refcount_inc(&b->active);
	rx2->service		= b;
	rx2->srx		= rx1->srx;
	rx2->call_id_backlog	= call_id_backlog;
	rx2->min_sec_level	= rx1->min_sec_level;
	rx2->local		= rxrpc_get_local(rx1->local);
	atomic_inc(&rx1->local->active_users);
	rx2->sk.sk_state	= RXRPC_SERVER_LISTENING;
	call_id_backlog = NULL;
	ret = 0;

error_unlock:
	release_sock(&rx1->sk);
	kfree(call_id_backlog);
error:
	fput(sock1->file);
	return ret;
}

/*
 * Splice into a call.  The call to send as part of must have been set with
 * setsockopt(RXRPC_SELECT_CALL_FOR_SEND).
 */
static ssize_t rxrpc_sendpage(struct socket *sock, struct page *page, int offset,
			      size_t size, int flags)
{
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	struct rxrpc_call *call;
	ssize_t ret;

	_enter("{%d},,%u,%zu,%x", rx->sk.sk_state, offset, size, flags);

	lock_sock(&rx->sk);

	read_lock_bh(&rx->recvmsg_lock);
	call = rx->selected_send_call;
	if (!call) {
		read_unlock_bh(&rx->recvmsg_lock);
		release_sock(&rx->sk);
		return -EBADSLT;
	}

	rxrpc_get_call(call, rxrpc_call_got);
	read_unlock_bh(&rx->recvmsg_lock);

	ret = mutex_lock_interruptible(&call->user_mutex);
	release_sock(&rx->sk);
	if (ret == 0) {
		ret = rxrpc_do_sendpage(rx, call, page, offset, size, flags);
		mutex_unlock(&call->user_mutex);
	}

	rxrpc_put_call(call, rxrpc_call_put);
	_leave(" = %zd", ret);
	return ret;
}

/*
 * Set the default call for 'targetless' operations such as splice(), SIOCINQ
 * and SIOCOUTQ and also as a filter for recvmsg().  Calling this function
 * always clears the old call attachment, and specifying a call_id
 * of 0 doesn't attach a new call.
 */
static int rxrpc_set_select_call(struct rxrpc_sock *rx, unsigned long call_id,
				 int optname)
{
	struct rxrpc_call *call, *old;

	write_lock_bh(&rx->recvmsg_lock);
	if (optname == RXRPC_SELECT_CALL_FOR_RECV) {
		old = rx->selected_recv_call;
		rx->selected_recv_call = NULL;
	} else {
		old = rx->selected_send_call;
		rx->selected_send_call = NULL;
	}
	write_unlock_bh(&rx->recvmsg_lock);

	if (old)
		rxrpc_put_call(old, rxrpc_call_put);

	if (!call_id)
		return 0;

	call = rxrpc_find_call_by_user_ID(rx, call_id);
	if (!call)
		return -EBADSLT;

	switch (call->state) {
	case RXRPC_CALL_UNINITIALISED:
	case RXRPC_CALL_SERVER_PREALLOC:
	case RXRPC_CALL_SERVER_SECURING:
		rxrpc_put_call(call, rxrpc_call_put);
		return -EBUSY;
	default:
		write_lock_bh(&rx->recvmsg_lock);
		if (optname == RXRPC_SELECT_CALL_FOR_RECV)
			rx->selected_recv_call = call;
		else
			rx->selected_send_call = call;
		write_unlock_bh(&rx->recvmsg_lock);
	}
	return 0;
}

/*
 * set RxRPC socket options
 */
static int rxrpc_setsockopt(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen)
{
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	unsigned long long call_id;
	unsigned int min_sec_level;
	u16 service_upgrade[2];
	int ret, fd;

	_enter(",%d,%d,,%d", level, optname, optlen);

	lock_sock(&rx->sk);
	ret = -EOPNOTSUPP;

	if (level == SOL_RXRPC) {
		switch (optname) {
		case RXRPC_EXCLUSIVE_CONNECTION:
			ret = -EINVAL;
			if (optlen != 0)
				goto error;
			ret = -EISCONN;
			if (rx->sk.sk_state != RXRPC_UNBOUND)
				goto error;
			rx->exclusive = true;
			goto success;

		case RXRPC_SECURITY_KEY:
			ret = -EINVAL;
			if (rx->key)
				goto error;
			ret = -EISCONN;
			if (rx->sk.sk_state != RXRPC_UNBOUND)
				goto error;
			ret = rxrpc_set_key(rx, optval, optlen);
			goto error;

		case RXRPC_SECURITY_KEYRING:
			ret = -EINVAL;
			if (rx->key)
				goto error;
			ret = -EISCONN;
			if (rx->sk.sk_state != RXRPC_UNBOUND)
				goto error;
			ret = rxrpc_server_keyring(rx, optval, optlen);
			goto error;

		case RXRPC_MIN_SECURITY_LEVEL:
			ret = -EINVAL;
			if (optlen != sizeof(unsigned int))
				goto error;
			ret = -EISCONN;
			if (rx->sk.sk_state != RXRPC_UNBOUND)
				goto error;
			ret = copy_from_sockptr(&min_sec_level, optval,
				       sizeof(unsigned int));
			if (ret < 0)
				goto error;
			ret = -EINVAL;
			if (min_sec_level > RXRPC_SECURITY_MAX)
				goto error;
			rx->min_sec_level = min_sec_level;
			goto success;

		case RXRPC_UPGRADEABLE_SERVICE:
			ret = -EINVAL;
			if (optlen != sizeof(service_upgrade))
				goto error;
			ret = -EISCONN;
			if (rx->sk.sk_state != RXRPC_SERVER_BOUND)
				goto error;
			ret = -EFAULT;
			if (copy_from_sockptr(service_upgrade, optval,
					   sizeof(service_upgrade)) != 0)
				goto error;
			mutex_lock(&rx->local->services_lock);
			ret = rxrpc_bind_service_upgrade(rx, service_upgrade[0],
							 service_upgrade[1]);
			mutex_unlock(&rx->local->services_lock);
			if (ret < 0)
				goto error;
			goto success;

		case RXRPC_BIND_CHANNEL:
			ret = -EINVAL;
			if (optlen != sizeof(fd))
				goto error;
			ret = -EFAULT;
			if (copy_from_sockptr(&fd, optval, sizeof(fd)) != 0)
				goto error;
			ret = rxrpc_bind_channel(rx, fd);
			if (ret < 0)
				goto error;
			goto success;

		case RXRPC_SELECT_CALL_FOR_RECV:
		case RXRPC_SELECT_CALL_FOR_SEND:
#warning compat_setsockopt disappeared
			ret = -EINVAL;
			if (optlen != sizeof(call_id))
				goto error;
			ret = -EFAULT;
			if (copy_from_sockptr(&call_id, optval,
					      sizeof(call_id)) != 0)
				goto error;
			ret = rxrpc_set_select_call(rx, call_id, optname);
			goto error;

		default:
			goto error;
		}
	} else {
		goto error;
	}

success:
	ret = 0;
error:
	release_sock(&rx->sk);
	return ret;
}

/*
 * Get socket options.
 */
static int rxrpc_getsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int __user *_optlen)
{
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	unsigned long call_id;
	int optlen;
	int ret;

	if (level != SOL_RXRPC)
		return -EOPNOTSUPP;

	if (get_user(optlen, _optlen))
		return -EFAULT;

	lock_sock(&rx->sk);

	switch (optname) {
	case RXRPC_SUPPORTED_CMSG:
		ret = -ETOOSMALL;
		if (optlen < sizeof(int))
			break;
		ret = -EFAULT;
		if (put_user(RXRPC__SUPPORTED - 1, (int __user *)optval) ||
		    put_user(sizeof(int), _optlen))
			break;
		ret = 0;
		break;

	case RXRPC_SELECT_CALL_FOR_RECV:
		ret = -ETOOSMALL;
		if (optlen < sizeof(unsigned long))
			break;
		read_lock_bh(&rx->recvmsg_lock);
		call_id = rx->selected_recv_call ?
			rx->selected_recv_call->user_call_ID : 0;
		read_unlock_bh(&rx->recvmsg_lock);
		ret = -EFAULT;
		if (put_user(call_id, (unsigned long __user *)optval) ||
		    put_user(sizeof(unsigned long), _optlen))
			break;
		ret = 0;
		break;

	case RXRPC_SELECT_CALL_FOR_SEND:
		ret = -ETOOSMALL;
		if (optlen < sizeof(unsigned long))
			break;
		read_lock_bh(&rx->recvmsg_lock);
		call_id = rx->selected_send_call ?
			rx->selected_send_call->user_call_ID : 0;
		read_unlock_bh(&rx->recvmsg_lock);
		ret = -EFAULT;
		if (put_user(call_id, (unsigned long __user *)optval) ||
		    put_user(sizeof(unsigned long), _optlen))
			break;
		ret = 0;
		break;

	default:
		ret = -EOPNOTSUPP;
		break;
	}

	release_sock(&rx->sk);
	return ret;
}

/*
 * permit an RxRPC socket to be polled
 */
static __poll_t rxrpc_poll(struct file *file, struct socket *sock,
			       poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct rxrpc_sock *rx = rxrpc_sk(sk);
	struct rxrpc_service *b = rx->service;
	__poll_t mask;

	sock_poll_wait(file, sock, wait);
	mask = 0;

	/* the socket is readable if there are any messages waiting on the Rx
	 * queue */
	if (!list_empty(&rx->recvmsg_q))
		mask |= EPOLLIN | EPOLLRDNORM;

	/* the socket is writable if there is space to add new data to the
	 * socket; there is no guarantee that any particular call in progress
	 * on the socket may have space in the Tx ACK window */
	if (rxrpc_writable(sk))
		mask |= EPOLLOUT | EPOLLWRNORM;

	if (b &&
	    !list_empty(&b->to_be_accepted) &&
	    CIRC_CNT(rx->call_id_backlog_head, rx->call_id_backlog_tail,
		     RXRPC_BACKLOG_MAX) == 0)
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

/*
 * create an RxRPC socket
 */
static int rxrpc_create(struct net *net, struct socket *sock, int protocol,
			int kern)
{
	struct rxrpc_net *rxnet;
	struct rxrpc_sock *rx;
	struct sock *sk;

	_enter("%p,%d", sock, protocol);

	/* we support transport protocol UDP/UDP6 only */
	if (protocol != PF_INET &&
	    IS_ENABLED(CONFIG_AF_RXRPC_IPV6) && protocol != PF_INET6)
		return -EPROTONOSUPPORT;

	if (sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->ops = &rxrpc_rpc_ops;
	sock->state = SS_UNCONNECTED;

	sk = sk_alloc(net, PF_RXRPC, GFP_KERNEL, &rxrpc_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sock_set_flag(sk, SOCK_RCU_FREE);
	sk->sk_state		= RXRPC_UNBOUND;
	sk->sk_write_space	= rxrpc_write_space;
	sk->sk_destruct		= rxrpc_sock_destructor;

	rx = rxrpc_sk(sk);
	rx->family = protocol;
	rx->calls = RB_ROOT;

	INIT_LIST_HEAD(&rx->sock_calls);
	INIT_LIST_HEAD(&rx->recvmsg_q);
	INIT_LIST_HEAD(&rx->accepting_link);
	rwlock_init(&rx->recvmsg_lock);
	rwlock_init(&rx->call_lock);
	memset(&rx->srx, 0, sizeof(rx->srx));

	rxnet = rxrpc_net(sock_net(&rx->sk));
	mutex_lock(&rxnet->local_mutex);
	hlist_add_head_rcu(&rx->ns_link, &rxnet->sockets);
	mutex_unlock(&rxnet->local_mutex);

	timer_reduce(&rxnet->peer_keepalive_timer, jiffies + 1);

	_leave(" = 0 [%p]", rx);
	return 0;
}

/*
 * Kill all the calls on a socket and shut it down.
 */
static int rxrpc_shutdown(struct socket *sock, int flags)
{
	struct sock *sk = sock->sk;
	int ret = 0;

	_enter("%p,%d", sk, flags);

	if (flags != SHUT_RDWR)
		return -EOPNOTSUPP;
	if (sk->sk_state == RXRPC_CLOSE)
		return -ESHUTDOWN;

	lock_sock(sk);

	spin_lock_bh(&sk->sk_receive_queue.lock);
	if (sk->sk_state < RXRPC_CLOSE) {
		sk->sk_state = RXRPC_CLOSE;
		sk->sk_shutdown = SHUTDOWN_MASK;
	} else {
		ret = -ESHUTDOWN;
	}
	spin_unlock_bh(&sk->sk_receive_queue.lock);
	release_sock(sk);
	return ret;
}

/*
 * RxRPC socket destructor
 */
static void rxrpc_sock_destructor(struct sock *sk)
{
	_enter("%p", sk);

	rxrpc_purge_queue(&sk->sk_receive_queue);

	WARN_ON(refcount_read(&sk->sk_wmem_alloc));
	WARN_ON(!sk_unhashed(sk));
	WARN_ON(sk->sk_socket);

	if (!sock_flag(sk, SOCK_DEAD)) {
		printk("Attempt to release alive rxrpc socket: %p\n", sk);
		return;
	}
}

/*
 * release an RxRPC socket
 */
static int rxrpc_release_sock(struct sock *sk)
{
	struct rxrpc_sock *rx = rxrpc_sk(sk);
	struct rxrpc_net *rxnet = rxrpc_net(sock_net(&rx->sk));

	_enter("%p{%d,%d}", sk, sk->sk_state, refcount_read(&sk->sk_refcnt));

	/* declare the socket closed for business */
	sock_orphan(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;
	if (rx->service)
		rxrpc_deactivate_service(rx);

	if (rx->selected_recv_call) {
		rxrpc_put_call(rx->selected_recv_call, rxrpc_call_put);
		rx->selected_recv_call = NULL;
	}

	if (rx->selected_send_call) {
		rxrpc_put_call(rx->selected_send_call, rxrpc_call_put);
		rx->selected_send_call = NULL;
	}

	/* We want to kill off all connections from a service socket
	 * as fast as possible because we can't share these; client
	 * sockets, on the other hand, can share an endpoint.
	 */
	switch (sk->sk_state) {
	case RXRPC_SERVER_BOUND:
	case RXRPC_SERVER_LISTENING:
	case RXRPC_SERVER_LISTEN_DISABLED:
		rx->local->service_closed = true;
		break;
	}

	spin_lock_bh(&sk->sk_receive_queue.lock);
	sk->sk_state = RXRPC_CLOSE;
	spin_unlock_bh(&sk->sk_receive_queue.lock);

	/* try to flush out this socket */
	if (rx->service) {
		kfree(rx->call_id_backlog);
		rxrpc_put_service(rxnet, rx->service);
	}
	rxrpc_release_calls_on_socket(rx);
	flush_workqueue(rxrpc_workqueue);
	rxrpc_purge_queue(&sk->sk_receive_queue);

	mutex_lock(&rxnet->local_mutex);
	hlist_del_rcu(&rx->ns_link);
	mutex_unlock(&rxnet->local_mutex);

	rxrpc_unuse_local(rx->local);
	rxrpc_put_local(rx->local);
	rx->local = NULL;
	key_put(rx->key);
	rx->key = NULL;
	sock_put(sk);

	_leave(" = 0");
	return 0;
}

/*
 * release an RxRPC BSD socket on close() or equivalent
 */
static int rxrpc_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	_enter("%p{%p}", sock, sk);

	if (!sk)
		return 0;

	sock->sk = NULL;

	return rxrpc_release_sock(sk);
}

/*
 * RxRPC network protocol
 */
static const struct proto_ops rxrpc_rpc_ops = {
	.family		= PF_RXRPC,
	.owner		= THIS_MODULE,
	.release	= rxrpc_release,
	.bind		= rxrpc_bind,
	.connect	= rxrpc_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= rxrpc_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= rxrpc_listen,
	.shutdown	= rxrpc_shutdown,
	.setsockopt	= rxrpc_setsockopt,
	.getsockopt	= rxrpc_getsockopt,
	.sendmsg	= rxrpc_sendmsg,
	.sendpage	= rxrpc_sendpage,
	.recvmsg	= rxrpc_recvmsg,
	.splice_read	= rxrpc_splice_read,
	.mmap		= sock_no_mmap,
};

static struct proto rxrpc_proto = {
	.name		= "RXRPC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct rxrpc_sock),
	.max_header	= sizeof(struct rxrpc_wire_header),
};

static const struct net_proto_family rxrpc_family_ops = {
	.family	= PF_RXRPC,
	.create = rxrpc_create,
	.owner	= THIS_MODULE,
};

/*
 * initialise and register the RxRPC protocol
 */
static int __init af_rxrpc_init(void)
{
	int ret = -1;
	unsigned int tmp;

	BUILD_BUG_ON(sizeof(struct rxrpc_skb_priv) > sizeof_field(struct sk_buff, cb));

	get_random_bytes(&tmp, sizeof(tmp));
	tmp &= 0x3fffffff;
	if (tmp == 0)
		tmp = 1;
	idr_set_cursor(&rxrpc_client_conn_ids, tmp);

	ret = -ENOMEM;
	rxrpc_call_jar = kmem_cache_create(
		"rxrpc_call_jar", sizeof(struct rxrpc_call), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!rxrpc_call_jar) {
		pr_notice("Failed to allocate call jar\n");
		goto error_call_jar;
	}

	rxrpc_workqueue = alloc_workqueue("krxrpcd", 0, 1);
	if (!rxrpc_workqueue) {
		pr_notice("Failed to allocate work queue\n");
		goto error_work_queue;
	}

	ret = rxrpc_init_security();
	if (ret < 0) {
		pr_crit("Cannot initialise security\n");
		goto error_security;
	}

	ret = register_pernet_device(&rxrpc_net_ops);
	if (ret)
		goto error_pernet;

	ret = proto_register(&rxrpc_proto, 1);
	if (ret < 0) {
		pr_crit("Cannot register protocol\n");
		goto error_proto;
	}

	ret = sock_register(&rxrpc_family_ops);
	if (ret < 0) {
		pr_crit("Cannot register socket family\n");
		goto error_sock;
	}

	ret = register_key_type(&key_type_rxrpc);
	if (ret < 0) {
		pr_crit("Cannot register client key type\n");
		goto error_key_type;
	}

	ret = register_key_type(&key_type_rxrpc_s);
	if (ret < 0) {
		pr_crit("Cannot register server key type\n");
		goto error_key_type_s;
	}

	ret = rxrpc_sysctl_init();
	if (ret < 0) {
		pr_crit("Cannot register sysctls\n");
		goto error_sysctls;
	}

	return 0;

error_sysctls:
	unregister_key_type(&key_type_rxrpc_s);
error_key_type_s:
	unregister_key_type(&key_type_rxrpc);
error_key_type:
	sock_unregister(PF_RXRPC);
error_sock:
	proto_unregister(&rxrpc_proto);
error_proto:
	unregister_pernet_device(&rxrpc_net_ops);
error_pernet:
	rxrpc_exit_security();
error_security:
	destroy_workqueue(rxrpc_workqueue);
error_work_queue:
	kmem_cache_destroy(rxrpc_call_jar);
error_call_jar:
	return ret;
}

/*
 * unregister the RxRPC protocol
 */
static void __exit af_rxrpc_exit(void)
{
	_enter("");
	rxrpc_sysctl_exit();
	unregister_key_type(&key_type_rxrpc_s);
	unregister_key_type(&key_type_rxrpc);
	sock_unregister(PF_RXRPC);
	proto_unregister(&rxrpc_proto);
	unregister_pernet_device(&rxrpc_net_ops);
	ASSERTCMP(atomic_read(&rxrpc_n_tx_skbs), ==, 0);
	ASSERTCMP(atomic_read(&rxrpc_n_rx_skbs), ==, 0);

	/* Make sure the local and peer records pinned by any dying connections
	 * are released.
	 */
	rcu_barrier();
	rxrpc_destroy_client_conn_ids();

	destroy_workqueue(rxrpc_workqueue);
	rxrpc_exit_security();
	kmem_cache_destroy(rxrpc_call_jar);
	_leave("");
}

module_init(af_rxrpc_init);
module_exit(af_rxrpc_exit);
