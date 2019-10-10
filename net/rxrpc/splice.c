// SPDX-License-Identifier: GPL-2.0-or-later
/* RxRPC splice-read implementation
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/export.h>
#include <linux/splice.h>
#include <linux/sched/signal.h>

#include <net/sock.h>
#include <net/af_rxrpc.h>
#include "ar-internal.h"

static void rxrpc_splice_notify_rx(struct sock *sk, struct rxrpc_call *call,
				   unsigned long user_id)
{
	wake_up(&call->waitq);
}

/*
 * Transfer messages to a splice.  This keeps processing packets until the pipe
 * is filled and we find either more DATA (returns 0) or the end of the DATA
 * (returns 1).  If more packets are required, it returns -EAGAIN and if the
 * call has failed it returns -EIO.
 */
static int rxrpc_splice_read_data(struct socket *sock, struct rxrpc_call *call,
				  struct pipe_inode_info *pipe,
				  unsigned int splice_flags,
				  size_t len, size_t *_offset)
{
	struct rxrpc_skb_priv *sp;
	struct sk_buff *skb;
	rxrpc_seq_t seq = 0;
	size_t remain;
	unsigned int rx_pkt_offset, rx_pkt_len;
	int copy, ret = -EAGAIN, ret2;

	rx_pkt_offset = call->rx_pkt_offset;
	rx_pkt_len = call->rx_pkt_len;

	if (rxrpc_call_has_failed(call)) {
		seq = call->ackr_window - 1;
		ret = -EIO;
		goto done;
	}

	if (test_bit(RXRPC_CALL_RECVMSG_READ_ALL, &call->flags)) {
		seq = call->ackr_window - 1;
		ret = 1;
		goto done;
	}

	/* No one else can be removing stuff from the queue, so we shouldn't
	 * need the Rx lock to walk it.
	 */
	while ((skb = skb_peek(&call->recvmsg_queue))) {
		rxrpc_see_skb(skb, rxrpc_skb_see_recvmsg);
		sp = rxrpc_skb(skb);
		seq = sp->hdr.seq;

		trace_rxrpc_receive(call, rxrpc_receive_front,
				    sp->hdr.serial, seq);

		if (rx_pkt_offset == 0) {
			ret2 = rxrpc_verify_data(call, skb);
			trace_rxrpc_recvdata(call, rxrpc_recvmsg_next, seq,
					     sp->offset, sp->len, ret2);
			if (ret2 < 0) {
				ret = ret2;
				goto out;
			}
			rx_pkt_offset = sp->offset;
			rx_pkt_len = sp->len;
		} else {
			trace_rxrpc_recvdata(call, rxrpc_recvmsg_cont, seq,
					     rx_pkt_offset, rx_pkt_len, 0);
		}

	try_another_transfer:
		/* We have to handle short, empty and used-up DATA packets. */
		remain = len - *_offset;
		copy = rx_pkt_len;
		if (copy > remain)
			copy = remain;
		if (copy > 0) {
			if (!(sp->hdr.flags & RXRPC_LAST_PACKET))
				splice_flags |= SPLICE_F_MORE;
			else if (copy < rx_pkt_len)
				splice_flags |= SPLICE_F_MORE;
			else
				splice_flags &= ~SPLICE_F_MORE;

			ret2 = skb_splice_bits(skb, sock->sk, rx_pkt_offset,
					       pipe, copy, splice_flags);
			if (ret2 < 0) {
				trace_rxrpc_recvdata(call, rxrpc_recvmsg_splice_full, seq,
						     rx_pkt_offset, rx_pkt_len, ret2);
				if (ret2 == -EAGAIN)
					ret2 = -EXFULL;
				ret = ret2;
				goto out;
			}
			trace_rxrpc_recvdata(call, rxrpc_recvmsg_splice_skb, seq,
					     rx_pkt_offset, rx_pkt_len, ret2);
			copy = ret2;

			/* handle piecemeal consumption of data packets */
			rx_pkt_offset += copy;
			rx_pkt_len -= copy;
			*_offset += copy;
		}

		if (*_offset >= len) {
			trace_rxrpc_recvdata(call, rxrpc_recvmsg_full, seq,
					     rx_pkt_offset, rx_pkt_len, 0);
			ret = 0;
			break;
		}

		if (rx_pkt_len > 0)
			goto try_another_transfer;

		/* The whole packet has been transferred. */
		if (rxrpc_rotate_rx_window(call)) {
			trace_rxrpc_recvmsg(call->debug_id, rxrpc_recvmsg_last, 1);
			ret = 1;
		}
		rx_pkt_offset = 0;
		rx_pkt_len = 0;
	}

out:
	call->rx_pkt_offset = rx_pkt_offset;
	call->rx_pkt_len = rx_pkt_len;
done:
	trace_rxrpc_recvdata(call, rxrpc_recvmsg_data_return, seq,
			     rx_pkt_offset, rx_pkt_len, ret);
	if (ret == -EAGAIN)
		set_bit(RXRPC_CALL_RX_IS_IDLE, &call->flags);
	return ret;
}

/*
 * Loop around waiting and splicing data for a specific call.  The caller has
 * unhooked the call from the usual notification mechanism so that we get
 * notified directly.
 */
static ssize_t rxrpc_splice_read_call(struct socket *sock,
				      struct rxrpc_call *call,
				      struct pipe_inode_info *pipe, size_t len,
				      unsigned int splice_flags)
{
	ssize_t ret = -EAGAIN, copied = 0;
	size_t partial;
	bool nonblock = splice_flags & SPLICE_F_NONBLOCK;

	DEFINE_WAIT(wait);

	do {
		if (!rxrpc_call_is_complete(call) &&
		    skb_queue_empty(&call->recvmsg_queue)) {
			ret = -EWOULDBLOCK;
			if (nonblock)
				break;

			/* Wait for something to happen */
			ret = wait_event_interruptible_exclusive(
				call->waitq,
				({
					rxrpc_call_is_complete(call) ||
						!skb_queue_empty(&call->recvmsg_queue) ||
						signal_pending(current);
				}));
			trace_rxrpc_recvmsg(call->debug_id, rxrpc_recvmsg_wait, ret);
			if (ret < 0)
				break;
		}

		/* We've dropped the socket lock, so we need to lock the call
		 * against interference by sendmsg.
		 */
		if (!mutex_trylock(&call->user_mutex)) {
			if (splice_flags & SPLICE_F_NONBLOCK)
				return -EWOULDBLOCK;
			if (mutex_lock_interruptible(&call->user_mutex) < 0)
				return -ERESTARTSYS;
		}

		partial = 0;
		ret = rxrpc_splice_read_data(sock, call, pipe, splice_flags,
					     len, &partial);
		mutex_unlock(&call->user_mutex);
		copied += partial;
		len -= partial;
	} while (len > 0 && ret == -EAGAIN);

	if (ret == 1)
		return copied;
	if (ret == -EAGAIN || ret == -EWOULDBLOCK ||
	    ret == -ERESTARTSYS || ret == -EINTR)
		return copied ?: ret;
	if (ret == -EXFULL)
		return copied ?: -EAGAIN;
	return ret;
}

/*
 * Read data from the call specified by setsockopt(RXRPC_SELECT_CALL_FOR_RECV)
 * and splice it into a pipe.
 */
ssize_t rxrpc_splice_read(struct socket *sock, loff_t *ppos,
			  struct pipe_inode_info *pipe, size_t len,
			  unsigned int splice_flags)
{
	struct rxrpc_call *call;
	struct rxrpc_sock *rx = rxrpc_sk(sock->sk);
	ssize_t ret;

	_enter("%zu", len);

	if (unlikely(!ppos))
		return -ESPIPE;
	if (!len)
		return 0;

	lock_sock(&rx->sk);
	call = rx->selected_recv_call;
	if (!call) {
		release_sock(&rx->sk);
		return -EBADSLT;
	}

	trace_rxrpc_recvmsg(call->debug_id, rxrpc_recvmsg_splice, 0);

	/* Switch the notification mechanism to tell us about the call rather
	 * than queuing the call for recvmsg() to deal with and remove the call
	 * from the recvmsg queue.
	 */
	ret = 0;
	spin_lock(&call->notify_lock);
	if (!call->notify_rx)
		call->notify_rx = rxrpc_splice_notify_rx;
	else
		ret = -EBUSY;
	spin_unlock(&call->notify_lock);
	if (ret < 0) {
		release_sock(&rx->sk);
		return -EBADSLT;
	}

	spin_lock(&rx->recvmsg_lock);
	if (list_empty(&call->recvmsg_link)) {
		rxrpc_get_call(call, rxrpc_call_get_splice_read);
	} else {
		trace_rxrpc_recvmsg(call->debug_id, rxrpc_recvmsg_dequeue, 0);
		list_del_init(&call->recvmsg_link);
		rx->nr_recvmsg--;
	}
	spin_unlock(&rx->recvmsg_lock);

	/* We can now drop the socket lock and do the read. */
	release_sock(&rx->sk);

	ret = rxrpc_splice_read_call(sock, call, pipe, len, splice_flags);

	/* Make the call visible to recvmsg() once again */
	spin_lock(&call->notify_lock);
	call->notify_rx = NULL;
	spin_unlock(&call->notify_lock);

	if (rxrpc_call_is_complete(call) ||
	    !skb_queue_empty(&call->recvmsg_queue)) {
		trace_rxrpc_recvmsg(call->debug_id,
				    rxrpc_recvmsg_splice_requeue, 0);
		rxrpc_notify_socket(call);
	}

	trace_rxrpc_recvmsg(call->debug_id, rxrpc_recvmsg_return, ret);
	rxrpc_put_call(call, rxrpc_call_put_splice_read);
	_leave(" = %zd", ret);
	return ret;
}
