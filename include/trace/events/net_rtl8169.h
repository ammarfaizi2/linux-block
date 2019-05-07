/* Realtek RTL8169 tracepoints
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM net_rtl8169

#if !defined(_TRACE_NET_RTL8169_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NET_RTL8169_H

#include <linux/tracepoint.h>
#include <linux/errqueue.h>


TRACE_EVENT(net_rtl8169_interrupt,
	    TP_PROTO(struct net_device *netdev, u16 status),

	    TP_ARGS(netdev, status),

	    TP_STRUCT__entry(
		    __field(u16,			status		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->status = status;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s st=%x", __entry->name, __entry->status)
	    );

TRACE_EVENT(net_rtl8169_poll,
	    TP_PROTO(struct net_device *netdev, int work_done),

	    TP_ARGS(netdev, work_done),

	    TP_STRUCT__entry(
		    __field(int,			work_done	)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->work_done = work_done;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s wd=%d", __entry->name, __entry->work_done)
	    );

TRACE_EVENT(net_rtl8169_napi_rx,
	    TP_PROTO(struct net_device *netdev, unsigned int count, u32 budget),

	    TP_ARGS(netdev, count, budget),

	    TP_STRUCT__entry(
		    __field(unsigned int,		count		)
		    __field(u32,			budget		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->count = count;
		    __entry->budget = budget;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s count=%d/%d",
		      __entry->name, __entry->count, __entry->budget)
	    );

TRACE_EVENT(net_rtl8169_napi_tx,
	    TP_PROTO(struct net_device *netdev, unsigned int tx_left),

	    TP_ARGS(netdev, tx_left),

	    TP_STRUCT__entry(
		    __field(unsigned int,		tx_left		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->tx_left = tx_left;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s l=%u",
		      __entry->name, __entry->tx_left)
	    );

TRACE_EVENT(net_rtl8169_tx,
	    TP_PROTO(struct net_device *netdev, unsigned int dirty_tx,
		     unsigned int cur_tx, unsigned int n),

	    TP_ARGS(netdev, dirty_tx, cur_tx, n),

	    TP_STRUCT__entry(
		    __field(unsigned int,		dirty_tx	)
		    __field(unsigned int,		cur_tx		)
		    __field(unsigned int,		n		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->dirty_tx = dirty_tx;
		    __entry->cur_tx = cur_tx;
		    __entry->n = n;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s p=%u/%u n=%u",
		      __entry->name, __entry->dirty_tx, __entry->cur_tx,
		      __entry->n)
	    );

#endif /* _TRACE_NET_RTL8169_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
