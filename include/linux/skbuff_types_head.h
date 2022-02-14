/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_SKBUFF_TYPES_HEAD_H
#define _LINUX_SKBUFF_TYPES_HEAD_H

#include <linux/spinlock_types.h>

struct sk_buff_head {
	/* These two members must be first to match sk_buff. */
	struct_group_tagged(sk_buff_list, list,
		struct sk_buff	*next;
		struct sk_buff	*prev;
	);

	__u32		qlen;
	spinlock_t	lock;
};

struct sk_buff;

#endif	/* _LINUX_SKBUFF_TYPES_HEAD_H */
