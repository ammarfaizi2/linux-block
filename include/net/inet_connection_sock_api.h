/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * NET		Generic infrastructure for INET connection oriented protocols.
 *
 *		Definitions for inet_connection_sock
 *
 * Authors:	Many people, see the TCP sources
 *
 *		From code originally in TCP
 */
#ifndef _INET_CONNECTION_SOCK_API_H
#define _INET_CONNECTION_SOCK_API_H

#include <net/inet_connection_sock_types.h>

#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/poll.h>
#include <linux/kernel.h>
#include <linux/sockptr.h>
#include <linux/percpu_counter.h>

#include <net/inet_sock.h>
#include <net/request_sock.h>

/* Cancel timers, when they are not required. */
#undef INET_CSK_CLEAR_TIMERS

#define ICSK_TIME_RETRANS	1	/* Retransmit timer */
#define ICSK_TIME_DACK		2	/* Delayed ack timer */
#define ICSK_TIME_PROBE0	3	/* Zero window probe timer */
#define ICSK_TIME_LOSS_PROBE	5	/* Tail loss probe timer */
#define ICSK_TIME_REO_TIMEOUT	6	/* Reordering timer */

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

struct sock *inet_csk_clone_lock(const struct sock *sk,
				 const struct request_sock *req,
				 const gfp_t priority);

enum inet_csk_ack_state_t {
	ICSK_ACK_SCHED	= 1,
	ICSK_ACK_TIMER  = 2,
	ICSK_ACK_PUSHED = 4,
	ICSK_ACK_PUSHED2 = 8,
	ICSK_ACK_NOW = 16	/* Send the next ACK immediately (once) */
};

void inet_csk_init_xmit_timers(struct sock *sk,
			       void (*retransmit_handler)(struct timer_list *),
			       void (*delack_handler)(struct timer_list *),
			       void (*keepalive_handler)(struct timer_list *));
void inet_csk_clear_xmit_timers(struct sock *sk);

static inline void inet_csk_schedule_ack(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_SCHED;
}

static inline int inet_csk_ack_scheduled(const struct sock *sk)
{
	return inet_csk(sk)->icsk_ack.pending & ICSK_ACK_SCHED;
}

static inline void inet_csk_delack_init(struct sock *sk)
{
	memset(&inet_csk(sk)->icsk_ack, 0, sizeof(inet_csk(sk)->icsk_ack));
}

void inet_csk_delete_keepalive_timer(struct sock *sk);
void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long timeout);

static inline void inet_csk_clear_xmit_timer(struct sock *sk, const int what)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0) {
		icsk->icsk_pending = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
#endif
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.pending = 0;
		icsk->icsk_ack.retry = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_delack_timer);
#endif
	} else {
		pr_debug("inet_csk BUG: unknown timer value\n");
	}
}

/*
 *	Reset the retransmission timer
 */
void inet_csk_reset_xmit_timer(struct sock *sk, const int what,
			       unsigned long when,
			       const unsigned long max_when);

static inline unsigned long
inet_csk_rto_backoff(const struct inet_connection_sock *icsk,
		     unsigned long max_when)
{
        u64 when = (u64)icsk->icsk_rto << icsk->icsk_backoff;

        return (unsigned long)min_t(u64, when, max_when);
}

struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern);

int inet_csk_get_port(struct sock *sk, unsigned short snum);

struct dst_entry *inet_csk_route_req(const struct sock *sk, struct flowi4 *fl4,
				     const struct request_sock *req);
struct dst_entry *inet_csk_route_child_sock(const struct sock *sk,
					    struct sock *newsk,
					    const struct request_sock *req);

struct sock *inet_csk_reqsk_queue_add(struct sock *sk,
				      struct request_sock *req,
				      struct sock *child);
void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
				   unsigned long timeout);
struct sock *inet_csk_complete_hashdance(struct sock *sk, struct sock *child,
					 struct request_sock *req,
					 bool own_req);

static inline void inet_csk_reqsk_queue_added(struct sock *sk)
{
	reqsk_queue_added(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_len(const struct sock *sk)
{
	return reqsk_queue_len(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_is_full(const struct sock *sk)
{
	return inet_csk_reqsk_queue_len(sk) >= sk->sk_max_ack_backlog;
}

bool inet_csk_reqsk_queue_drop(struct sock *sk, struct request_sock *req);
void inet_csk_reqsk_queue_drop_and_put(struct sock *sk, struct request_sock *req);
void inet_csk_prepare_for_destroy_sock(struct sock *sk);
void inet_csk_destroy_sock(struct sock *sk);
void inet_csk_prepare_forced_close(struct sock *sk);

/*
 * LISTEN is a special case for poll..
 */
static inline __poll_t inet_csk_listen_poll(const struct sock *sk)
{
	return !reqsk_queue_empty(&inet_csk(sk)->icsk_accept_queue) ?
			(EPOLLIN | EPOLLRDNORM) : 0;
}

int inet_csk_listen_start(struct sock *sk);
void inet_csk_listen_stop(struct sock *sk);

void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr);

/* update the fast reuse flag when adding a socket */
void inet_csk_update_fastreuse(struct inet_bind_bucket *tb,
			       struct sock *sk);

struct dst_entry *inet_csk_update_pmtu(struct sock *sk, u32 mtu);

#define TCP_PINGPONG_THRESH	3

static inline void inet_csk_enter_pingpong_mode(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pingpong = TCP_PINGPONG_THRESH;
}

static inline void inet_csk_exit_pingpong_mode(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pingpong = 0;
}

static inline bool inet_csk_in_pingpong_mode(struct sock *sk)
{
	return inet_csk(sk)->icsk_ack.pingpong >= TCP_PINGPONG_THRESH;
}

static inline void inet_csk_inc_pingpong_cnt(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ack.pingpong < U8_MAX)
		icsk->icsk_ack.pingpong++;
}

static inline bool inet_csk_has_ulp(struct sock *sk)
{
	return inet_sk(sk)->is_icsk && !!inet_csk(sk)->icsk_ulp_ops;
}

#endif /* _INET_CONNECTION_SOCK_API_H */
