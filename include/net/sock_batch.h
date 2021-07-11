/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _SOCK_BATCH_H
#define _SOCK_BATCH_H

#include <net/sock.h>
#include <linux/percpu_counter_api.h>

#define SK_ALLOC_PERCPU_COUNTER_BATCH 16

static inline void sk_sockets_allocated_dec(struct sock *sk)
{
	percpu_counter_add_batch(sk->sk_prot->sockets_allocated, -1,
				 SK_ALLOC_PERCPU_COUNTER_BATCH);
}

static inline void sk_sockets_allocated_inc(struct sock *sk)
{
	percpu_counter_add_batch(sk->sk_prot->sockets_allocated, 1,
				 SK_ALLOC_PERCPU_COUNTER_BATCH);
}

static inline u64
sk_sockets_allocated_read_positive(struct sock *sk)
{
	return percpu_counter_read_positive(sk->sk_prot->sockets_allocated);
}

static inline int
proto_sockets_allocated_sum_positive(struct proto *prot)
{
	return percpu_counter_sum_positive(prot->sockets_allocated);
}

#endif	/* _SOCK_BATCH_H */
