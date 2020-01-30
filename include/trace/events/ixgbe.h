/* Realtek IXGBE tracepoints
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
#define TRACE_SYSTEM ixgbe

#if !defined(_TRACE_IXGBE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IXGBE_H

#include <linux/tracepoint.h>
#include <linux/errqueue.h>


TRACE_EVENT(ixgbe_intr,
	    TP_PROTO(struct net_device *netdev, u32 eicr),

	    TP_ARGS(netdev, eicr),

	    TP_STRUCT__entry(
		    __field(u32,			eicr		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->eicr = eicr;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s eicr=%x", __entry->name, __entry->eicr)
	    );

TRACE_EVENT(ixgbe_poll,
	    TP_PROTO(struct net_device *netdev, int budget),

	    TP_ARGS(netdev, budget),

	    TP_STRUCT__entry(
		    __field(int,			budget		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->budget = budget;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s b=%d", __entry->name, __entry->budget)
	    );

TRACE_EVENT(ixgbe_rx,
	    TP_PROTO(struct net_device *netdev, unsigned int count, int budget),

	    TP_ARGS(netdev, count, budget),

	    TP_STRUCT__entry(
		    __field(unsigned int,		count		)
		    __field(int,			budget		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->count = count;
		    __entry->budget = budget;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s c=%u/%d",
		      __entry->name, __entry->count, __entry->budget)
	    );

TRACE_EVENT(ixgbe_tx,
	    TP_PROTO(struct net_device *netdev, unsigned int count),

	    TP_ARGS(netdev, count),

	    TP_STRUCT__entry(
		    __field(unsigned int,		count		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->count = count;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s c=%u",
		      __entry->name, __entry->count)
	    );

TRACE_EVENT(ixgbe_tx_done,
	    TP_PROTO(struct net_device *netdev, unsigned int count),

	    TP_ARGS(netdev, count),

	    TP_STRUCT__entry(
		    __field(unsigned int,		count		)
		    __array(char,			name, IFNAMSIZ	)
			     ),

	    TP_fast_assign(
		    __entry->count = count;
		    memcpy(__entry->name, netdev->name, IFNAMSIZ);
			   ),

	    TP_printk("%s c=%u",
		      __entry->name, __entry->count)
	    );

#endif /* _TRACE_IXGBE_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
