/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *  include/linux/eventpoll.h ( Efficient event polling implementation )
 *  Copyright (C) 2001,...,2006	 Davide Libenzi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#ifndef _UAPI_LINUX_EVENTPOLL_H
#define _UAPI_LINUX_EVENTPOLL_H

/* For O_CLOEXEC */
#include <linux/fcntl.h>
#include <linux/types.h>

/* Flags for epoll_create1.  */
#define EPOLL_CLOEXEC O_CLOEXEC

/* Valid opcodes to issue to sys_epoll_ctl() */
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

/* Epoll event masks */
#define EPOLLIN		(__force __poll_t)0x00000001
#define EPOLLPRI	(__force __poll_t)0x00000002
#define EPOLLOUT	(__force __poll_t)0x00000004
#define EPOLLERR	(__force __poll_t)0x00000008
#define EPOLLHUP	(__force __poll_t)0x00000010
#define EPOLLNVAL	(__force __poll_t)0x00000020
#define EPOLLRDNORM	(__force __poll_t)0x00000040
#define EPOLLRDBAND	(__force __poll_t)0x00000080
#define EPOLLWRNORM	(__force __poll_t)0x00000100
#define EPOLLWRBAND	(__force __poll_t)0x00000200
#define EPOLLMSG	(__force __poll_t)0x00000400
#define EPOLLRDHUP	(__force __poll_t)0x00002000

/* Set exclusive wakeup mode for the target file descriptor */
#define EPOLLEXCLUSIVE	((__force __poll_t)(1U << 28))

/*
 * Request the handling of system wakeup events so as to prevent system suspends
 * from happening while those events are being processed.
 *
 * Assuming neither EPOLLET nor EPOLLONESHOT is set, system suspends will not be
 * re-allowed until epoll_wait is called again after consuming the wakeup
 * event(s).
 *
 * Requires CAP_BLOCK_SUSPEND
 */
#define EPOLLWAKEUP	((__force __poll_t)(1U << 29))

/* Set the One Shot behaviour for the target file descriptor */
#define EPOLLONESHOT	((__force __poll_t)(1U << 30))

/* Set the Edge Triggered behaviour for the target file descriptor */
#define EPOLLET		((__force __poll_t)(1U << 31))

/*
 * On x86-64 make the 64bit structure have the same alignment as the
 * 32bit structure. This makes 32bit emulation easier.
 *
 * UML/x86_64 needs the same packing as x86_64
 */
#ifdef __x86_64__
#define EPOLL_PACKED __attribute__((packed))
#else
#define EPOLL_PACKED
#endif

struct epoll_event {
	__poll_t events;
	__u64 data;
} EPOLL_PACKED;

#define EPOLL_USERPOLL_HEADER_MAGIC 0xeb01eb01
#define EPOLL_USERPOLL_HEADER_SIZE  128

/*
 * Item, shared with userspace.  Unfortunately we can't embed epoll_event
 * structure, because it is badly aligned on all 64-bit archs, except
 * x86-64 (see EPOLL_PACKED).  sizeof(epoll_uitem) == 16
 */
struct epoll_uitem {
	__poll_t ready_events;
	__poll_t events;
	__u64 data;
};

/*
 * Header, shared with userspace. sizeof(epoll_uheader) == 128
 */
struct epoll_uheader {
	__u32 magic;          /* epoll user header magic */
	__u32 header_length;  /* length of the header + items */
	__u32 max_items_nr;   /* max number of items */
	__u32 __reserved[128 / sizeof(__u32) - 3];

	/* Table of descriptors.  The notifications index into this. */
	struct epoll_uitem items[]
		__attribute__((__aligned__(EPOLL_USERPOLL_HEADER_SIZE)));
};

#endif /* _UAPI_LINUX_EVENTPOLL_H */
