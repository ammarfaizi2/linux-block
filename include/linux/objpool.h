/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_OBJPOOL_H
#define _LINUX_OBJPOOL_H

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>

/*
 * objpool: ring-array based lockless MPMC/FIFO queues
 *
 * Copyright: wuqiang.matt@bytedance.com
 *
 * The object pool is a scalable implementaion of high performance queue
 * for objects allocation and reclamation, such as kretprobe instances.
 *
 * With leveraging per-cpu ring-array to mitigate the hot spots of memory
 * contention, it could deliver near-linear scalability for high parallel
 * cases. Meanwhile, it also achieves high throughput with benifiting from
 * warmed cache on each core.
 *
 * The object pool are best suited for the following cases:
 * 1) memory allocation or reclamation is prohibited or too expensive
 * 2) the objects are allocated/used/reclaimed very frequently
 *
 * Before using, you must be aware of it's limitations:
 * 1) Maximum number of objects is determined during pool initializing
 * 2) The memory of objects won't be freed until the poll is de-allocated
 * 3) Both allocation and reclamation could be nested
 */

/*
 * objpool_slot: per-cpu ring array
 *
 * Represents a cpu-local array-based ring buffer, its size is specialized
 * during initialization of object pool.
 *
 * The objpool_slot is allocated from local memory for NUMA system, and to
 * be kept compact in a single cacheline. ages[] is stored just after the
 * body of objpool_slot, and ents[] is after ages[]. ages[] describes the
 * revision of epoch of the item, solely used to avoid ABA. ents[] contains
 * the object pointers.
 *
 * The default size of objpool_slot is a single cacheline, aka. 64 bytes.
 *
 * 64bit:
 *        4      8      12     16        32                 64
 * | head | tail | size | mask | ages[4] | ents[4]: (8 * 4) |
 *
 * 32bit:
 *        4      8      12     16        32        48       64
 * | head | tail | size | mask | ages[4] | ents[4] | unused |
 *
 */

struct objpool_slot {
	uint32_t                os_head;	/* head of ring array */
	uint32_t                os_tail;	/* tail of ring array */
	uint32_t                os_size;	/* max item slots, pow of 2 */
	uint32_t                os_mask;	/* os_size - 1 */
/*
 *	uint32_t                os_ages[];	// ring epoch id
 *	void                   *os_ents[];	// objects array
 */
};

/* caller-specified object initial callback to setup each object, only called once */
typedef int (*objpool_init_node_cb)(void *context, void *obj);

/* caller-specified cleanup callback for private objects/pool/context */
typedef int (*objpool_release_cb)(void *context, void *ptr, uint32_t flags);

/* called for object releasing: ptr points to an object */
#define OBJPOOL_FLAG_NODE        (0x00000001)
/* for user pool and context releasing, ptr could be NULL */
#define OBJPOOL_FLAG_POOL        (0x00001000)
/* the object or pool to be released is user-managed */
#define OBJPOOL_FLAG_USER        (0x00008000)

/*
 * objpool_head: object pooling metadata
 */

struct objpool_head {
	uint32_t                oh_objsz;	/* object & element size */
	uint32_t                oh_nobjs;	/* total objs (pre-allocated) */
	uint32_t                oh_nents;	/* max objects per cpuslot */
	uint32_t                oh_ncpus;	/* num of possible cpus */
	uint32_t                oh_in_user:1;	/* user-specified buffer */
	uint32_t                oh_in_slot:1;	/* objs alloced with slots */
	uint32_t                oh_vmalloc:1;	/* alloc from vmalloc zone */
	gfp_t                   oh_gfp;		/* k/vmalloc gfp flags */
	uint32_t                oh_sz_pool;	/* user pool size in byes */
	void                   *oh_pool;	/* user managed memory pool */
	struct objpool_slot   **oh_slots;	/* array of percpu slots */
	uint32_t               *oh_sz_slots;	/* size in bytes of slots */
	objpool_release_cb      oh_release;	/* resource cleanup callback */
	void                   *oh_context;	/* caller-provided context */
};

/* initialize object pool and pre-allocate objects */
int objpool_init(struct objpool_head *oh,
		int nobjs, int max, int objsz,
		gfp_t gfp, void *context,
		objpool_init_node_cb objinit,
		objpool_release_cb release);

/* add objects in batch from user provided pool */
int objpool_populate(struct objpool_head *oh, void *buf,
			int size, int objsz, void *context,
			objpool_init_node_cb objinit);

/* add pre-allocated object (managed by user) to objpool */
int objpool_add(void *obj, struct objpool_head *oh);

/* allocate an object from objects pool */
void *objpool_pop(struct objpool_head *oh);

/* reclaim an object and return it back to objects pool */
int objpool_push(void *node, struct objpool_head *oh);

/* cleanup the whole object pool (including all chained objects) */
void objpool_fini(struct objpool_head *oh);

/* whether the object is pre-allocated with percpu slots */
static inline int objpool_is_inslot(void *obj, struct objpool_head *oh)
{
	void *slot;
	int i;

	if (!obj)
		return 0;

	for (i = 0; i < oh->oh_ncpus; i++) {
		slot = oh->oh_slots[i];
		if (obj >= slot && obj < slot + oh->oh_sz_slots[i])
			return 1;
	}

	return 0;
}

/* whether the object is from user pool (batched adding) */
static inline int objpool_is_inpool(void *obj, struct objpool_head *oh)
{
	return (obj && oh->oh_pool && obj >= oh->oh_pool &&
		obj < oh->oh_pool + oh->oh_sz_pool);
}

#endif /* _LINUX_OBJPOOL_H */
