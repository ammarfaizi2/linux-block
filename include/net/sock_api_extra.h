/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _SOCK_API_EXTRA_H
#define _SOCK_API_EXTRA_H

#include <net/sock_api.h>

/* OOB backlog add */
static inline void __sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	/* dont let skb dst not refcounted, we are going to leave rcu lock */
	skb_dst_force(skb);

	if (!sk->sk_backlog.tail)
		WRITE_ONCE(sk->sk_backlog.head, skb);
	else
		sk->sk_backlog.tail->next = skb;

	WRITE_ONCE(sk->sk_backlog.tail, skb);
	skb->next = NULL;
}

/*
 * Take into account size of receive queue and backlog queue
 * Do not take into account this skb truesize,
 * to allow even a single big packet to come.
 */
static inline bool sk_rcvqueues_full(const struct sock *sk, unsigned int limit)
{
	unsigned int qsize = sk->sk_backlog.len + atomic_read(&sk->sk_rmem_alloc);

	return qsize > limit;
}

/* The per-socket spinlock must be held here. */
static inline __must_check int sk_add_backlog(struct sock *sk, struct sk_buff *skb,
					      unsigned int limit)
{
	if (sk_rcvqueues_full(sk, limit))
		return -ENOBUFS;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC))
		return -ENOMEM;

	__sk_add_backlog(sk, skb);
	sk->sk_backlog.len += skb->truesize;
	return 0;
}

int __sk_backlog_rcv(struct sock *sk, struct sk_buff *skb);

INDIRECT_CALLABLE_DECLARE(int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb));
INDIRECT_CALLABLE_DECLARE(int tcp_v6_do_rcv(struct sock *sk, struct sk_buff *skb));

static inline int sk_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (sk_memalloc_socks() && skb_pfmemalloc(skb))
		return __sk_backlog_rcv(sk, skb);

	return INDIRECT_CALL_INET(sk->sk_backlog_rcv,
				  tcp_v6_do_rcv,
				  tcp_v4_do_rcv,
				  sk, skb);
}

static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	sk->sk_dst_pending_confirm = 0;
	old_dst = rcu_dereference_protected(sk->sk_dst_cache,
					    lockdep_sock_is_held(sk));
	rcu_assign_pointer(sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	sk->sk_dst_pending_confirm = 0;
	old_dst = xchg((__force struct dst_entry **)&sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	__sk_dst_set(sk, NULL);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	sk_dst_set(sk, NULL);
}

#endif	/* _SOCK_API_EXTRA_H */
