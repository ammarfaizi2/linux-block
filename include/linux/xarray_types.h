/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_XARRAY_TYPES_H
#define _LINUX_XARRAY_TYPES_H
/*
 * eXtensible Arrays
 * Copyright (c) 2017 Microsoft Corporation
 * Author: Matthew Wilcox <willy@infradead.org>
 *
 * See Documentation/core-api/xarray.rst for how to use the XArray.
 */

#include <linux/gfp_types.h>
#include <linux/math.h>
#include <linux/spinlock_types.h>

/*
 * The bottom two bits of the entry determine how the XArray interprets
 * the contents:
 *
 * 00: Pointer entry
 * 10: Internal entry
 * x1: Value entry or tagged pointer
 *
 * Attempting to store internal entries in the XArray is a bug.
 *
 * Most internal entries are pointers to the next node in the tree.
 * The following internal entries have a special meaning:
 *
 * 0-62: Sibling entries
 * 256: Retry entry
 * 257: Zero entry
 *
 * Errors are also represented as internal entries, but use the negative
 * space (-4094 to -2).  They're never stored in the slots array; only
 * returned by the normal API.
 */

#define BITS_PER_XA_VALUE	(BITS_PER_LONG - 1)

/**
 * struct xa_limit - Represents a range of IDs.
 * @min: The lowest ID to allocate (inclusive).
 * @max: The maximum ID to allocate (inclusive).
 *
 * This structure is used either directly or via the XA_LIMIT() macro
 * to communicate the range of IDs that are valid for allocation.
 * Three common ranges are predefined for you:
 * * xa_limit_32b	- [0 - UINT_MAX]
 * * xa_limit_31b	- [0 - INT_MAX]
 * * xa_limit_16b	- [0 - USHRT_MAX]
 */
struct xa_limit {
	u32 max;
	u32 min;
};

#define XA_LIMIT(_min, _max) (struct xa_limit) { .min = _min, .max = _max }

#define xa_limit_32b	XA_LIMIT(0, UINT_MAX)
#define xa_limit_31b	XA_LIMIT(0, INT_MAX)
#define xa_limit_16b	XA_LIMIT(0, USHRT_MAX)

typedef unsigned __bitwise xa_mark_t;
#define XA_MARK_0		((__force xa_mark_t)0U)
#define XA_MARK_1		((__force xa_mark_t)1U)
#define XA_MARK_2		((__force xa_mark_t)2U)
#define XA_PRESENT		((__force xa_mark_t)8U)
#define XA_MARK_MAX		XA_MARK_2
#define XA_FREE_MARK		XA_MARK_0

enum xa_lock_type {
	XA_LOCK_IRQ = 1,
	XA_LOCK_BH = 2,
};

/*
 * Values for xa_flags.  The radix tree stores its GFP flags in the xa_flags,
 * and we remain compatible with that.
 */
#define XA_FLAGS_LOCK_IRQ	((__force gfp_t)XA_LOCK_IRQ)
#define XA_FLAGS_LOCK_BH	((__force gfp_t)XA_LOCK_BH)
#define XA_FLAGS_TRACK_FREE	((__force gfp_t)4U)
#define XA_FLAGS_ZERO_BUSY	((__force gfp_t)8U)
#define XA_FLAGS_ALLOC_WRAPPED	((__force gfp_t)16U)
#define XA_FLAGS_ACCOUNT	((__force gfp_t)32U)
#define XA_FLAGS_MARK(mark)	((__force gfp_t)((1U << __GFP_BITS_SHIFT) << \
						(__force unsigned)(mark)))

/* ALLOC is for a normal 0-based alloc.  ALLOC1 is for an 1-based alloc */
#define XA_FLAGS_ALLOC	(XA_FLAGS_TRACK_FREE | XA_FLAGS_MARK(XA_FREE_MARK))
#define XA_FLAGS_ALLOC1	(XA_FLAGS_TRACK_FREE | XA_FLAGS_ZERO_BUSY)

/**
 * struct xarray - The anchor of the XArray.
 * @xa_lock: Lock that protects the contents of the XArray.
 *
 * To use the xarray, define it statically or embed it in your data structure.
 * It is a very small data structure, so it does not usually make sense to
 * allocate it separately and keep a pointer to it in your data structure.
 *
 * You may use the xa_lock to protect your own data structures as well.
 */
/*
 * If all of the entries in the array are NULL, @xa_head is a NULL pointer.
 * If the only non-NULL entry in the array is at index 0, @xa_head is that
 * entry.  If any other entry in the array is non-NULL, @xa_head points
 * to an @xa_node.
 */
struct xarray {
	spinlock_t	xa_lock;
/* private: The rest of the data structure is not to be used directly. */
	gfp_t		xa_flags;
	void __rcu *	xa_head;
};

#define XARRAY_INIT(name, flags) {				\
	.xa_lock = __SPIN_LOCK_UNLOCKED(name.xa_lock),		\
	.xa_flags = flags,					\
	.xa_head = NULL,					\
}

/**
 * DEFINE_XARRAY_FLAGS() - Define an XArray with custom flags.
 * @name: A string that names your XArray.
 * @flags: XA_FLAG values.
 *
 * This is intended for file scope definitions of XArrays.  It declares
 * and initialises an empty XArray with the chosen name and flags.  It is
 * equivalent to calling xa_init_flags() on the array, but it does the
 * initialisation at compiletime instead of runtime.
 */
#define DEFINE_XARRAY_FLAGS(name, flags)				\
	struct xarray name = XARRAY_INIT(name, flags)

/**
 * DEFINE_XARRAY() - Define an XArray.
 * @name: A string that names your XArray.
 *
 * This is intended for file scope definitions of XArrays.  It declares
 * and initialises an empty XArray with the chosen name.  It is equivalent
 * to calling xa_init() on the array, but it does the initialisation at
 * compiletime instead of runtime.
 */
#define DEFINE_XARRAY(name) DEFINE_XARRAY_FLAGS(name, 0)

/**
 * DEFINE_XARRAY_ALLOC() - Define an XArray which allocates IDs starting at 0.
 * @name: A string that names your XArray.
 *
 * This is intended for file scope definitions of allocating XArrays.
 * See also DEFINE_XARRAY().
 */
#define DEFINE_XARRAY_ALLOC(name) DEFINE_XARRAY_FLAGS(name, XA_FLAGS_ALLOC)

/**
 * DEFINE_XARRAY_ALLOC1() - Define an XArray which allocates IDs starting at 1.
 * @name: A string that names your XArray.
 *
 * This is intended for file scope definitions of allocating XArrays.
 * See also DEFINE_XARRAY().
 */
#define DEFINE_XARRAY_ALLOC1(name) DEFINE_XARRAY_FLAGS(name, XA_FLAGS_ALLOC1)

/**
 * xa_init_flags() - Initialise an empty XArray with flags.
 * @xa: XArray.
 * @flags: XA_FLAG values.
 *
 * If you need to initialise an XArray with special flags (eg you need
 * to take the lock from interrupt context), use this function instead
 * of xa_init().
 *
 * Context: Any context.
 */
static inline void xa_init_flags(struct xarray *xa, gfp_t flags)
{
	spin_lock_init(&xa->xa_lock);
	xa->xa_flags = flags;
	xa->xa_head = NULL;
}

/**
 * xa_init() - Initialise an empty XArray.
 * @xa: XArray.
 *
 * An empty XArray is full of NULL entries.
 *
 * Context: Any context.
 */
static inline void xa_init(struct xarray *xa)
{
	xa_init_flags(xa, 0);
}

/**
 * xa_empty() - Determine if an array has any present entries.
 * @xa: XArray.
 *
 * Context: Any context.
 * Return: %true if the array contains only NULL pointers.
 */
static inline bool xa_empty(const struct xarray *xa)
{
	return xa->xa_head == NULL;
}

/* Everything below here is the Advanced API.  Proceed with caution. */

/*
 * The xarray is constructed out of a set of 'chunks' of pointers.  Choosing
 * the best chunk size requires some tradeoffs.  A power of two recommends
 * itself so that we can walk the tree based purely on shifts and masks.
 * Generally, the larger the better; as the number of slots per level of the
 * tree increases, the less tall the tree needs to be.  But that needs to be
 * balanced against the memory consumption of each node.  On a 64-bit system,
 * xa_node is currently 576 bytes, and we get 7 of them per 4kB page.  If we
 * doubled the number of slots per node, we'd get only 3 nodes per 4kB page.
 */
#ifndef XA_CHUNK_SHIFT
#define XA_CHUNK_SHIFT		(CONFIG_BASE_SMALL ? 4 : 6)
#endif
#define XA_CHUNK_SIZE		(1UL << XA_CHUNK_SHIFT)
#define XA_CHUNK_MASK		(XA_CHUNK_SIZE - 1)
#define XA_MAX_MARKS		3
#define XA_MARK_LONGS		DIV_ROUND_UP(XA_CHUNK_SIZE, BITS_PER_LONG)

/*
 * @count is the count of every non-NULL element in the ->slots array
 * whether that is a value entry, a retry entry, a user pointer,
 * a sibling entry or a pointer to the next level of the tree.
 * @nr_values is the count of every element in ->slots which is
 * either a value entry or a sibling of a value entry.
 */
struct xa_node {
	unsigned char	shift;		/* Bits remaining in each slot */
	unsigned char	offset;		/* Slot offset in parent */
	unsigned char	count;		/* Total entry count */
	unsigned char	nr_values;	/* Value entry count */
	struct xa_node __rcu *parent;	/* NULL at top of tree */
	struct xarray	*array;		/* The array we belong to */
	union {
		struct list_head private_list;	/* For tree user */
		struct rcu_head	rcu_head;	/* Used when freeing node */
	};
	void __rcu	*slots[XA_CHUNK_SIZE];
	union {
		unsigned long	tags[XA_MAX_MARKS][XA_MARK_LONGS];
		unsigned long	marks[XA_MAX_MARKS][XA_MARK_LONGS];
	};
};

#endif /* _LINUX_XARRAY_TYPES_H */
