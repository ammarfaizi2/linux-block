// SPDX-License-Identifier: GPL-2.0-or-later
/* Management of Tx window, Tx resend, ACKs and out-of-sequence reception
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/circ_buf.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/udp.h>
#include <net/sock.h>
#include <net/af_rxrpc.h>
#include "ar-internal.h"

/*
 * Propose a PING ACK be sent.
 */
static void rxrpc_propose_ping(struct rxrpc_call *call,
			       bool immediate, bool background)
{
	if (immediate) {
		if (background &&
		    !test_and_set_bit(RXRPC_CALL_EV_PING, &call->events))
			rxrpc_queue_call(call);
	} else {
		unsigned long now = jiffies;
		unsigned long ping_at = now + rxrpc_idle_ack_delay;

		if (time_before(ping_at, call->ping_at)) {
			WRITE_ONCE(call->ping_at, ping_at);
			rxrpc_reduce_call_timer(call, ping_at, now,
						rxrpc_timer_set_for_ping);
		}
	}
}

/*
 * propose an ACK be sent
 */
static void __rxrpc_propose_ACK(struct rxrpc_call *call, u8 ack_reason,
				u32 serial, bool immediate, bool background,
				enum rxrpc_propose_ack_trace why)
{
	enum rxrpc_propose_ack_outcome outcome = rxrpc_propose_ack_use;
	unsigned long expiry = rxrpc_soft_ack_delay;
	s8 prior = rxrpc_ack_priority[ack_reason];

	/* Pings are handled specially because we don't want to accidentally
	 * lose a ping response by subsuming it into a ping.
	 */
	if (ack_reason == RXRPC_ACK_PING) {
		rxrpc_propose_ping(call, immediate, background);
		goto trace;
	}

	/* Update DELAY, IDLE, REQUESTED and PING_RESPONSE ACK serial
	 * numbers, but we don't alter the timeout.
	 */
	_debug("prior %u %u vs %u %u",
	       ack_reason, prior,
	       call->ackr_reason, rxrpc_ack_priority[call->ackr_reason]);
	if (ack_reason == call->ackr_reason) {
		if (RXRPC_ACK_UPDATEABLE & (1 << ack_reason)) {
			outcome = rxrpc_propose_ack_update;
			call->ackr_serial = serial;
		}
		if (!immediate)
			goto trace;
	} else if (prior > rxrpc_ack_priority[call->ackr_reason]) {
		call->ackr_reason = ack_reason;
		call->ackr_serial = serial;
	} else {
		outcome = rxrpc_propose_ack_subsume;
	}

	switch (ack_reason) {
	case RXRPC_ACK_REQUESTED:
		if (rxrpc_requested_ack_delay < expiry)
			expiry = rxrpc_requested_ack_delay;
		if (serial == 1)
			immediate = false;
		break;

	case RXRPC_ACK_DELAY:
		if (rxrpc_soft_ack_delay < expiry)
			expiry = rxrpc_soft_ack_delay;
		break;

	case RXRPC_ACK_IDLE:
		if (rxrpc_idle_ack_delay < expiry)
			expiry = rxrpc_idle_ack_delay;
		break;

	default:
		immediate = true;
		break;
	}

	if (test_bit(RXRPC_CALL_EV_ACK, &call->events)) {
		_debug("already scheduled");
	} else if (immediate || expiry == 0) {
		_debug("immediate ACK %lx", call->events);
		if (!test_and_set_bit(RXRPC_CALL_EV_ACK, &call->events) &&
		    background)
			rxrpc_queue_call(call);
	} else {
		unsigned long now = jiffies, ack_at;

		if (call->peer->srtt_us != 0)
			ack_at = usecs_to_jiffies(call->peer->srtt_us >> 3);
		else
			ack_at = expiry;

		ack_at += READ_ONCE(call->tx_backoff);
		ack_at += now;
		if (time_before(ack_at, call->ack_at)) {
			WRITE_ONCE(call->ack_at, ack_at);
			rxrpc_reduce_call_timer(call, ack_at, now,
						rxrpc_timer_set_for_ack);
		}
	}

trace:
	trace_rxrpc_propose_ack(call, why, ack_reason, serial, immediate,
				background, outcome);
}

/*
 * propose an ACK be sent, locking the call structure
 */
void rxrpc_propose_ACK(struct rxrpc_call *call, u8 ack_reason,
		       u32 serial, bool immediate, bool background,
		       enum rxrpc_propose_ack_trace why)
{
	spin_lock_bh(&call->lock);
	__rxrpc_propose_ACK(call, ack_reason, serial,
			    immediate, background, why);
	spin_unlock_bh(&call->lock);
}

/*
 * Handle congestion being detected by the retransmit timeout.
 */
static void rxrpc_congestion_timeout(struct rxrpc_call *call)
{
	set_bit(RXRPC_CALL_RETRANS_TIMEOUT, &call->flags);
}

/*
 * Perform retransmission of NAK'd and unack'd packets.
 */
static void rxrpc_resend(struct rxrpc_call *call, unsigned long now_j)
{
	struct rxrpc_txbuf *txb;
	struct rxrpc_local *local = call->peer->local;
	unsigned long resend_at;
	rxrpc_seq_t transmitted = READ_ONCE(call->tx_transmitted);
	ktime_t now, max_age, oldest, ack_ts;
	bool unacked = false;
	LIST_HEAD(retrans_queue);

	_enter("{%d,%d}", call->acks_hard_ack, call->tx_top);

	now = ktime_get_real();
	max_age = ktime_sub_us(now, jiffies_to_usecs(call->peer->rto_j));

	spin_lock(&call->tx_lock);

	/* Scan the packet list without dropping the lock and decide which of
	 * the packets in the Tx buffer we're going to resend and what the new
	 * resend timeout will be.
	 */
	trace_rxrpc_resend(call);
	oldest = now;
	list_for_each_entry(txb, &call->tx_buffer, call_link) {
		if (test_bit(RXRPC_TXBUF_ACKED, &txb->flags))
			continue;
		if (after(txb->seq, transmitted))
			break;
		if (after(ntohl(txb->wire.serial), call->acks_highest_serial))
			continue;

		rxrpc_see_txbuf(txb, rxrpc_txbuf_see_unacked);

		if (test_bit(RXRPC_TXBUF_RESENT, &txb->flags)) {
			if (ktime_after(txb->last_sent, max_age)) {
				if (ktime_before(txb->last_sent, oldest))
					oldest = txb->last_sent;
				continue;
			}
			unacked = true;
		}

		if (list_empty(&txb->tx_link)) {
			rxrpc_get_txbuf(txb, rxrpc_txbuf_get_retrans);
			rxrpc_get_call(call, rxrpc_call_got_tx);
			list_add_tail(&txb->tx_link, &retrans_queue);
			set_bit(RXRPC_TXBUF_RESENT, &txb->flags);
		}

		trace_rxrpc_retransmit(call, txb->seq,
				       ktime_to_ns(ktime_sub(txb->last_sent,
							     max_age)));
	}

	spin_unlock(&call->tx_lock);

	resend_at = nsecs_to_jiffies(ktime_to_ns(ktime_sub(now, oldest)));
	resend_at += jiffies + rxrpc_get_rto_backoff(call->peer,
						     !list_empty(&retrans_queue));
	WRITE_ONCE(call->resend_at, resend_at);

	if (unacked)
		rxrpc_congestion_timeout(call);

	/* If there was nothing that needed retransmission then it's likely
	 * that an ACK got lost somewhere.  Send a ping to find out instead of
	 * retransmitting data.
	 */
	if (list_empty(&retrans_queue)) {
		spin_lock_bh(&call->lock);
		rxrpc_reduce_call_timer(call, resend_at, now_j,
					rxrpc_timer_set_for_resend);
		spin_unlock_bh(&call->lock);
		ack_ts = ktime_sub(now, call->acks_latest_ts);
		if (ktime_to_us(ack_ts) < (call->peer->srtt_us >> 3))
			goto out;
		rxrpc_propose_ACK(call, RXRPC_ACK_PING, 0, true, false,
				  rxrpc_propose_ack_ping_for_lost_ack);
		rxrpc_send_ack_packet(call, true, NULL);
		goto out;
	}

	/* Push the packets to be retransmitted onto the transmission queue and
	 * wake up the transmitter worker.  Note that it's possible that an ACK
	 * might come in whilst a packet is on the queue.
	 */
	spin_lock(&local->tx_lock);
	if (rxrpc_is_client_call(call))
		rxrpc_expose_client_call(call);
	list_splice_tail(&retrans_queue, &local->tx_queue);
	spin_unlock(&local->tx_lock);
	rxrpc_wake_up_transmitter(local);

out:
	_leave("");
}

/*
 * Shrink the transmit queue.
 */
void rxrpc_shrink_call_tx_queue(struct rxrpc_call *call)
{
	struct rxrpc_txbuf *txb;
	rxrpc_seq_t hard_ack = smp_load_acquire(&call->acks_hard_ack);

	_enter("%x/%x/%x", call->tx_bottom, call->acks_hard_ack, call->tx_top);

	for (;;) {
		spin_lock(&call->tx_lock);
		txb = list_first_entry_or_null(&call->tx_buffer,
					       struct rxrpc_txbuf, call_link);
		if (!txb)
			break;
		hard_ack = smp_load_acquire(&call->acks_hard_ack);
		if (before(hard_ack, txb->seq))
			break;

		ASSERTCMP(txb->seq, ==, call->tx_bottom + 1);
		call->tx_bottom++;
		list_del_rcu(&txb->call_link);

		trace_rxrpc_txqueue(call, rxrpc_txqueue_dequeue);

		spin_unlock(&call->tx_lock);

		rxrpc_put_txbuf(txb, rxrpc_txbuf_put_rotated);
	}

	spin_unlock(&call->tx_lock);
}

/*
 * Handle retransmission and deferred ACK/abort generation.
 */
void rxrpc_process_call(struct work_struct *work)
{
	struct rxrpc_call *call =
		container_of(work, struct rxrpc_call, processor);
	rxrpc_serial_t *send_ack;
	unsigned long now, next, t;
	unsigned int iterations = 0;

	rxrpc_see_call(call);

	//printk("\n--------------------\n");
	_enter("{%d,%s,%lx}",
	       call->debug_id, rxrpc_call_states[call->state], call->events);

recheck_state:
	/* Limit the number of times we do this before returning to the manager */
	iterations++;
	if (iterations > 5)
		goto requeue;

	if (test_and_clear_bit(RXRPC_CALL_EV_ABORT, &call->events)) {
		rxrpc_send_abort_packet(call);
		goto recheck_state;
	}

	if (READ_ONCE(call->acks_hard_ack) != call->tx_bottom)
		rxrpc_shrink_call_tx_queue(call);

	if (call->state == RXRPC_CALL_COMPLETE) {
		rxrpc_delete_call_timer(call);
		goto out_put;
	}

	/* Work out if any timeouts tripped */
	now = jiffies;
	t = READ_ONCE(call->expect_rx_by);
	if (time_after_eq(now, t)) {
		trace_rxrpc_timer(call, rxrpc_timer_exp_normal, now);
		set_bit(RXRPC_CALL_EV_EXPIRED, &call->events);
	}

	t = READ_ONCE(call->expect_req_by);
	if (call->state == RXRPC_CALL_SERVER_RECV_REQUEST &&
	    time_after_eq(now, t)) {
		trace_rxrpc_timer(call, rxrpc_timer_exp_idle, now);
		set_bit(RXRPC_CALL_EV_EXPIRED, &call->events);
	}

	t = READ_ONCE(call->expect_term_by);
	if (time_after_eq(now, t)) {
		trace_rxrpc_timer(call, rxrpc_timer_exp_hard, now);
		set_bit(RXRPC_CALL_EV_EXPIRED, &call->events);
	}

	t = READ_ONCE(call->ack_at);
	if (time_after_eq(now, t)) {
		trace_rxrpc_timer(call, rxrpc_timer_exp_ack, now);
		cmpxchg(&call->ack_at, t, now + MAX_JIFFY_OFFSET);
		set_bit(RXRPC_CALL_EV_ACK, &call->events);
	}

	t = READ_ONCE(call->ack_lost_at);
	if (time_after_eq(now, t)) {
		trace_rxrpc_timer(call, rxrpc_timer_exp_lost_ack, now);
		cmpxchg(&call->ack_lost_at, t, now + MAX_JIFFY_OFFSET);
		set_bit(RXRPC_CALL_EV_ACK_LOST, &call->events);
	}

	t = READ_ONCE(call->keepalive_at);
	if (time_after_eq(now, t)) {
		trace_rxrpc_timer(call, rxrpc_timer_exp_keepalive, now);
		cmpxchg(&call->keepalive_at, t, now + MAX_JIFFY_OFFSET);
		rxrpc_propose_ACK(call, RXRPC_ACK_PING, 0, true, true,
				  rxrpc_propose_ack_ping_for_keepalive);
		set_bit(RXRPC_CALL_EV_PING, &call->events);
	}

	t = READ_ONCE(call->ping_at);
	if (time_after_eq(now, t)) {
		trace_rxrpc_timer(call, rxrpc_timer_exp_ping, now);
		cmpxchg(&call->ping_at, t, now + MAX_JIFFY_OFFSET);
		set_bit(RXRPC_CALL_EV_PING, &call->events);
	}

	t = READ_ONCE(call->resend_at);
	if (time_after_eq(now, t)) {
		trace_rxrpc_timer(call, rxrpc_timer_exp_resend, now);
		cmpxchg(&call->resend_at, t, now + MAX_JIFFY_OFFSET);
		set_bit(RXRPC_CALL_EV_RESEND, &call->events);
	}

	/* Process events */
	if (test_and_clear_bit(RXRPC_CALL_EV_EXPIRED, &call->events)) {
		if (test_bit(RXRPC_CALL_RX_HEARD, &call->flags) &&
		    (int)call->conn->hi_serial - (int)call->rx_serial > 0) {
			trace_rxrpc_call_reset(call);
			rxrpc_abort_call("EXP", call, 0, RX_USER_ABORT, -ECONNRESET);
		} else {
			rxrpc_abort_call("EXP", call, 0, RX_USER_ABORT, -ETIME);
		}
		set_bit(RXRPC_CALL_EV_ABORT, &call->events);
		goto recheck_state;
	}

	send_ack = NULL;
	if (test_and_clear_bit(RXRPC_CALL_EV_ACK_LOST, &call->events)) {
		call->acks_lost_top = call->tx_top;
		rxrpc_propose_ACK(call, RXRPC_ACK_PING, 0, true, false,
				  rxrpc_propose_ack_ping_for_lost_ack);
		send_ack = &call->acks_lost_ping;
	}

	if (test_and_clear_bit(RXRPC_CALL_EV_ACK, &call->events) ||
	    send_ack) {
		if (call->ackr_reason) {
			rxrpc_send_ack_packet(call, false, send_ack);
			goto recheck_state;
		}
	}

	if (test_and_clear_bit(RXRPC_CALL_EV_PING, &call->events)) {
		rxrpc_send_ack_packet(call, true, NULL);
		goto recheck_state;
	}

	if (test_and_clear_bit(RXRPC_CALL_EV_RESEND, &call->events) &&
	    call->state != RXRPC_CALL_CLIENT_RECV_REPLY) {
		rxrpc_resend(call, now);
		goto recheck_state;
	}

	/* Make sure the timer is restarted */
	next = call->expect_rx_by;

#define set(T) { t = READ_ONCE(T); if (time_before(t, next)) next = t; }

	set(call->expect_req_by);
	set(call->expect_term_by);
	set(call->ack_at);
	set(call->ack_lost_at);
	set(call->resend_at);
	set(call->keepalive_at);
	set(call->ping_at);

	now = jiffies;
	if (time_after_eq(now, next))
		goto recheck_state;

	rxrpc_reduce_call_timer(call, next, now, rxrpc_timer_restart);

	/* other events may have been raised since we started checking */
	if (call->events && call->state < RXRPC_CALL_COMPLETE)
		goto requeue;

out_put:
	rxrpc_put_call(call, rxrpc_call_put);
out:
	_leave("");
	return;

requeue:
	__rxrpc_queue_call(call);
	goto out;
}
