/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for a generic INET TIMEWAIT sock
 *
 *		From code originally in net/tcp.h
 */
#ifndef _INET_TIMEWAIT_SOCK_API
#define _INET_TIMEWAIT_SOCK_API

#include <net/inet_timewait_sock_types.h>

#include <net/net_namespace.h>

#include <net/inet_sock_types.h>


static inline struct inet_timewait_sock *inet_twsk(const struct sock *sk)
{
	return (struct inet_timewait_sock *)sk;
}

void inet_twsk_free(struct inet_timewait_sock *tw);
void inet_twsk_put(struct inet_timewait_sock *tw);

void inet_twsk_bind_unhash(struct inet_timewait_sock *tw,
			   struct inet_hashinfo *hashinfo);

struct inet_timewait_sock *inet_twsk_alloc(const struct sock *sk,
					   struct inet_timewait_death_row *dr,
					   const int state);

void inet_twsk_hashdance(struct inet_timewait_sock *tw, struct sock *sk,
			 struct inet_hashinfo *hashinfo);

void __inet_twsk_schedule(struct inet_timewait_sock *tw, int timeo,
			  bool rearm);

static inline void inet_twsk_schedule(struct inet_timewait_sock *tw, int timeo)
{
	__inet_twsk_schedule(tw, timeo, false);
}

static inline void inet_twsk_reschedule(struct inet_timewait_sock *tw, int timeo)
{
	__inet_twsk_schedule(tw, timeo, true);
}

void inet_twsk_deschedule_put(struct inet_timewait_sock *tw);

void inet_twsk_purge(struct inet_hashinfo *hashinfo, int family);

static inline
struct net *twsk_net(const struct inet_timewait_sock *twsk)
{
	return read_pnet(&twsk->tw_net);
}

static inline
void twsk_net_set(struct inet_timewait_sock *twsk, struct net *net)
{
	write_pnet(&twsk->tw_net, net);
}
#endif	/* _INET_TIMEWAIT_SOCK_API */
