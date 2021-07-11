/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _UDP_API_SOCK_H
#define _UDP_API_SOCK_H

#include <net/udp.h>
#include <net/sock_api.h>

static inline void udp_lib_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

static inline int udp_rqueue_get(struct sock *sk)
{
	return sk_rmem_alloc_get(sk) - READ_ONCE(udp_sk(sk)->forward_deficit);
}
#endif	/* _UDP_API_SOCK_H */
