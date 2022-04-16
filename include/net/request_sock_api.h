/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 */
#ifndef _REQUEST_SOCK_API_H
#define _REQUEST_SOCK_API_H

#include <net/request_sock_types.h>

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/refcount_api.h>

#include <net/sock_types.h>

static inline struct request_sock *inet_reqsk(const struct sock *sk)
{
	return (struct request_sock *)sk;
}

static inline struct sock *req_to_sk(struct request_sock *req)
{
	return (struct sock *)req;
}

void __reqsk_free(struct request_sock *req);

static inline void reqsk_free(struct request_sock *req)
{
	WARN_ON_ONCE(refcount_read(&req->rsk_refcnt) != 0);
	__reqsk_free(req);
}

static inline void reqsk_put(struct request_sock *req)
{
	if (refcount_dec_and_test(&req->rsk_refcnt))
		reqsk_free(req);
}

void reqsk_queue_alloc(struct request_sock_queue *queue);

void reqsk_fastopen_remove(struct sock *sk, struct request_sock *req,
			   bool reset);

static inline bool reqsk_queue_empty(const struct request_sock_queue *queue)
{
	return READ_ONCE(queue->rskq_accept_head) == NULL;
}

struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue, struct sock *parent);

static inline void reqsk_queue_removed(struct request_sock_queue *queue,
				       const struct request_sock *req)
{
	if (req->num_timeout == 0)
		atomic_dec(&queue->young);
	atomic_dec(&queue->qlen);
}

static inline void reqsk_queue_added(struct request_sock_queue *queue)
{
	atomic_inc(&queue->young);
	atomic_inc(&queue->qlen);
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return atomic_read(&queue->qlen);
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return atomic_read(&queue->young);
}

#endif /* _REQUEST_SOCK_API_H */
