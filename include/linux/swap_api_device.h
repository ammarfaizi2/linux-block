/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SWAP_API_DEVICE_H
#define _LINUX_SWAP_API_DEVICE_H

#include <linux/swap.h>

#include <linux/percpu-refcount-api.h>

#ifdef CONFIG_SWAP

static inline void put_swap_device(struct swap_info_struct *si)
{
	percpu_ref_put(&si->users);
}

#else /* CONFIG_SWAP */

static inline void put_swap_device(struct swap_info_struct *si)
{
}

#endif /* CONFIG_SWAP */

#endif /* _LINUX_SWAP_API_DEVICE_H */
