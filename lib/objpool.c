// SPDX-License-Identifier: GPL-2.0

#include <linux/objpool.h>

/*
 * objpool: ring-array based lockless MPMC/FIFO queues
 *
 * Copyright: wuqiang.matt@bytedance.com
 */

/* compute the suitable num of objects to be managed by slot */
static inline uint32_t __objpool_num_of_objs(uint32_t size)
{
	return rounddown_pow_of_two((size - sizeof(struct objpool_slot)) /
			(sizeof(uint32_t) + sizeof(void *)));
}

#define SLOT_AGES(s) ((uint32_t *)((char *)(s) + sizeof(struct objpool_slot)))
#define SLOT_ENTS(s) ((void **)((char *)(s) + sizeof(struct objpool_slot) + \
			sizeof(uint32_t) * (s)->os_size))
#define SLOT_OBJS(s) ((void *)((char *)(s) + sizeof(struct objpool_slot) + \
			(sizeof(uint32_t) + sizeof(void *)) * (s)->os_size))

/* allocate and initialize percpu slots */
static inline int
__objpool_init_percpu_slots(struct objpool_head *oh, uint32_t nobjs,
			void *context, objpool_init_node_cb objinit)
{
	uint32_t i, j, size, objsz, nents = oh->oh_nents;

	/* aligned object size by sizeof(void *) */
	objsz = ALIGN(oh->oh_objsz, sizeof(void *));
	/* shall we allocate objects along with objpool_slot */
	if (objsz)
		oh->oh_in_slot = 1;

	for (i = 0; i < oh->oh_ncpus; i++) {
		struct objpool_slot *os;
		uint32_t n;

		/* compute how many objects to be managed by this slot */
		n = nobjs / oh->oh_ncpus;
		if (i < (nobjs % oh->oh_ncpus))
			n++;
		size = sizeof(struct objpool_slot) + sizeof(void *) * nents +
		       sizeof(uint32_t) * nents + objsz * n;

		/* decide which pool shall the slot be allocated from */
		if (0 == i) {
			if ((oh->oh_gfp & GFP_ATOMIC) || size < PAGE_SIZE / 2)
				oh->oh_vmalloc = 0;
			else
				oh->oh_vmalloc = 1;
		}

		/* allocate percpu slot & objects from local memory */
		if (oh->oh_vmalloc)
			os = vmalloc_node(size, cpu_to_node(i));
		else
			os = kmalloc_node(size, oh->oh_gfp, cpu_to_node(i));
		if (!os)
			return -ENOMEM;

		/* initialize percpu slot for the i-th cpu */
		memset(os, 0, size);
		os->os_size = oh->oh_nents;
		os->os_mask = os->os_size - 1;
		oh->oh_slots[i] = os;
		oh->oh_sz_slots[i] = size;

		/*
		 * start from 2nd round to avoid conflict of 1st item.
		 * we assume that the head item is ready for retrieval
		 * iff head is equal to ages[head & mask]. but ages is
		 * initialized as 0, so in view of the caller of pop(),
		 * the 1st item (0th) is always ready, but fact could
		 * be: push() is stalled before the final update, thus
		 * the item being inserted will be lost forever.
		 */
		os->os_head = os->os_tail = oh->oh_nents;

		for (j = 0; oh->oh_in_slot && j < n; j++) {
			uint32_t *ages = SLOT_AGES(os);
			void **ents = SLOT_ENTS(os);
			void *obj = SLOT_OBJS(os) + j * objsz;
			uint32_t ie = os->os_tail & os->os_mask;

			/* perform object initialization */
			if (objinit) {
				int rc = objinit(context, obj);
				if (rc)
					return rc;
			}

			/* add obj into the ring array */
			ents[ie] = obj;
			ages[ie] = os->os_tail;
			os->os_tail++;
			oh->oh_nobjs++;
		}
	}

	return 0;
}

/* cleanup all percpu slots of the object pool */
static inline void __objpool_fini_percpu_slots(struct objpool_head *oh)
{
	uint32_t i;

	if (!oh->oh_slots)
		return;

	for (i = 0; i < oh->oh_ncpus; i++) {
		if (!oh->oh_slots[i])
			continue;
		if (oh->oh_vmalloc)
			vfree(oh->oh_slots[i]);
		else
			kfree(oh->oh_slots[i]);
	}
	kfree(oh->oh_slots);
	oh->oh_slots = NULL;
	oh->oh_sz_slots = NULL;
}

/**
 * objpool_init: initialize object pool and pre-allocate objects
 *
 * args:
 * @oh:    the object pool to be initialized, declared by the caller
 * @nojbs: total objects to be allocated by this object pool
 * @max:   max objs this objpool could manage, use nobjs if 0
 * @ojbsz: size of an object, to be pre-allocated if objsz is not 0
 * @gfp:   gfp flags of caller's context for memory allocation
 * @context: user context for object initialization callback
 * @objinit: object initialization callback for extra setting-up
 * @release: cleanup callback for private objects/pool/context
 *
 * return:
 *         0 for success, otherwise error code
 *
 * All pre-allocated objects are to be zeroed. Caller could do extra
 * initialization in objinit callback. The objinit callback will be
 * called once and only once after the slot allocation
 */
int objpool_init(struct objpool_head *oh,
		int nobjs, int max, int objsz,
		gfp_t gfp, void *context,
		objpool_init_node_cb objinit,
		objpool_release_cb release)
{
	uint32_t nents, cpus = num_possible_cpus();
	int rc;

	/* calculate percpu slot size (rounded to pow of 2) */
	if (max < nobjs)
		max = nobjs;
	nents = max / cpus;
	if (nents < __objpool_num_of_objs(L1_CACHE_BYTES))
		nents = __objpool_num_of_objs(L1_CACHE_BYTES);
	nents = roundup_pow_of_two(nents);
	while (nents * cpus < nobjs)
		nents = nents << 1;

	memset(oh, 0, sizeof(struct objpool_head));
	oh->oh_ncpus = cpus;
	oh->oh_objsz = objsz;
	oh->oh_nents = nents;
	oh->oh_gfp = gfp & ~__GFP_ZERO;
	oh->oh_context = context;
	oh->oh_release = release;

	/* allocate array for percpu slots */
	oh->oh_slots = kzalloc(oh->oh_ncpus * sizeof(void *) +
			       oh->oh_ncpus * sizeof(uint32_t), oh->oh_gfp);
	if (!oh->oh_slots)
		return -ENOMEM;
	oh->oh_sz_slots = (uint32_t *)&oh->oh_slots[oh->oh_ncpus];

	/* initialize per-cpu slots */
	rc = __objpool_init_percpu_slots(oh, nobjs, context, objinit);
	if (rc)
		__objpool_fini_percpu_slots(oh);

	return rc;
}
EXPORT_SYMBOL_GPL(objpool_init);

/* adding object to slot tail, the given slot mustn't be full */
static inline int __objpool_add_slot(void *obj, struct objpool_slot *os)
{
	uint32_t *ages = SLOT_AGES(os);
	void **ents = SLOT_ENTS(os);
	uint32_t tail = atomic_inc_return((atomic_t *)&os->os_tail) - 1;

	WRITE_ONCE(ents[tail & os->os_mask], obj);

	/* order matters: obj must be updated before tail updating */
	smp_store_release(&ages[tail & os->os_mask], tail);
	return 0;
}

/* adding object to slot, abort if the slot was already full */
static inline int __objpool_try_add_slot(void *obj, struct objpool_slot *os)
{
	uint32_t *ages = SLOT_AGES(os);
	void **ents = SLOT_ENTS(os);
	uint32_t head, tail;

	do {
		/* perform memory loading for both head and tail */
		head = READ_ONCE(os->os_head);
		tail = READ_ONCE(os->os_tail);
		/* just abort if slot is full */
		if (tail >= head + os->os_size)
			return -ENOENT;
		/* try to extend tail by 1 using CAS to avoid races */
		if (try_cmpxchg_acquire(&os->os_tail, &tail, tail + 1))
			break;
	} while (1);

	/* the tail-th of slot is reserved for the given obj */
	WRITE_ONCE(ents[tail & os->os_mask], obj);
	/* update epoch id to make this object available for pop() */
	smp_store_release(&ages[tail & os->os_mask], tail);
	return 0;
}

/**
 * objpool_populate: add objects from user provided pool in batch
 *
 * args:
 * @oh:  object pool
 * @buf: user buffer for pre-allocated objects
 * @size: size of user buffer
 * @objsz: size of object & element
 * @context: user context for objinit callback
 * @objinit: object initialization callback
 *
 * return: 0 or error code
 */
int objpool_populate(struct objpool_head *oh, void *buf, int size, int objsz,
		    void *context, objpool_init_node_cb objinit)
{
	int n = oh->oh_nobjs, used = 0, i;

	if (oh->oh_pool || !buf || size < objsz)
		return -EINVAL;
	if (oh->oh_objsz && oh->oh_objsz != objsz)
		return -EINVAL;
	if (oh->oh_context && context && oh->oh_context != context)
		return -EINVAL;
	if (oh->oh_nobjs >= oh->oh_ncpus * oh->oh_nents)
		return -ENOENT;

	WARN_ON_ONCE(((unsigned long)buf) & (sizeof(void *) - 1));
	WARN_ON_ONCE(((uint32_t)objsz) & (sizeof(void *) - 1));

	/* align object size by sizeof(void *) */
	oh->oh_objsz = objsz;
	objsz = ALIGN(objsz, sizeof(void *));
	if (objsz <= 0)
		return -EINVAL;

	while (used + objsz <= size) {
		void *obj = buf + used;

		/* perform object initialization */
		if (objinit) {
			int rc = objinit(context, obj);
			if (rc)
				return rc;
		}

		/* insert obj to its corresponding objpool slot */
		i = (n + used * oh->oh_ncpus/size) % oh->oh_ncpus;
		if (!__objpool_try_add_slot(obj, oh->oh_slots[i]))
			oh->oh_nobjs++;

		used += objsz;
	}

	if (!used)
		return -ENOENT;

	oh->oh_context = context;
	oh->oh_pool = buf;
	oh->oh_sz_pool = size;

	return 0;
}
EXPORT_SYMBOL_GPL(objpool_populate);

/**
 * objpool_add: add pre-allocated object to objpool during pool
 * initialization
 *
 * args:
 * @obj: object pointer to be added to objpool
 * @oh:  object pool to be inserted into
 *
 * return:
 *     0 or error code
 *
 * objpool_add_node doesn't handle race conditions, can only be
 * called during objpool initialization
 */
int objpool_add(void *obj, struct objpool_head *oh)
{
	uint32_t i, cpu;

	if (!obj)
		return -EINVAL;
	if (oh->oh_nobjs >= oh->oh_ncpus * oh->oh_nents)
		return -ENOENT;

	cpu = oh->oh_nobjs % oh->oh_ncpus;
	for (i = 0; i < oh->oh_ncpus; i++) {
		if (!__objpool_try_add_slot(obj, oh->oh_slots[cpu])) {
			oh->oh_nobjs++;
			return 0;
		}

		if (++cpu >= oh->oh_ncpus)
			cpu = 0;
	}

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(objpool_add);

/**
 * objpool_push: reclaim the object and return back to objects pool
 *
 * args:
 * @obj: object pointer to be pushed to object pool
 * @oh:  object pool
 *
 * return:
 *     0 or error code: it fails only when objects pool are full
 *
 * objpool_push is non-blockable, and can be nested
 */
int objpool_push(void *obj, struct objpool_head *oh)
{
	uint32_t cpu = raw_smp_processor_id();

	do {
		if (oh->oh_nobjs > oh->oh_nents) {
			if (!__objpool_try_add_slot(obj, oh->oh_slots[cpu]))
				return 0;
		} else {
			if (!__objpool_add_slot(obj, oh->oh_slots[cpu]))
				return 0;
		}
		if (++cpu >= oh->oh_ncpus)
			cpu = 0;
	} while (1);

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(objpool_push);

/* try to retrieve object from slot */
static inline void *__objpool_try_get_slot(struct objpool_slot *os)
{
	uint32_t *ages = SLOT_AGES(os);
	void **ents = SLOT_ENTS(os);
	/* do memory load of os_head to local head */
	uint32_t head = smp_load_acquire(&os->os_head);

	/* loop if slot isn't empty */
	while (head != READ_ONCE(os->os_tail)) {
		uint32_t id = head & os->os_mask, prev = head;

		/* do prefetching of object ents */
		prefetch(&ents[id]);

		/*
		 * check whether this item was ready for retrieval ? There's
		 * possibility * in theory * we might retrieve wrong object,
		 * in case ages[id] overflows when current task is sleeping,
		 * but it will take very very long to overflow an uint32_t
		 */
		if (smp_load_acquire(&ages[id]) == head) {
			/* node must have been udpated by push() */
			void *node = READ_ONCE(ents[id]);
			/* commit and move forward head of the slot */
			if (try_cmpxchg_release(&os->os_head, &head, head + 1))
				return node;
		}

		/* re-load head from memory continue trying */
		head = READ_ONCE(os->os_head);
		/*
		 * head stays unchanged, so it's very likely current pop()
		 * just preempted/interrupted an ongoing push() operation
		 */
		if (head == prev)
			break;
	}

	return NULL;
}

/**
 * objpool_pop: allocate an object from objects pool
 *
 * args:
 * @oh:  object pool
 *
 * return:
 *   object: NULL if failed (object pool is empty)
 *
 * objpool_pop can be nested, so can be used in any context.
 */
void *objpool_pop(struct objpool_head *oh)
{
	uint32_t i, cpu = raw_smp_processor_id();
	void *obj = NULL;

	for (i = 0; i < oh->oh_ncpus; i++) {
		struct objpool_slot *slot = oh->oh_slots[cpu];
		obj = __objpool_try_get_slot(slot);
		if (obj)
			break;
		if (++cpu >= oh->oh_ncpus)
			cpu = 0;
	}

	return obj;
}
EXPORT_SYMBOL_GPL(objpool_pop);

/**
 * objpool_fini: cleanup the whole object pool (releasing all objects)
 *
 * args:
 * @head: object pool to be released
 *
 */
void objpool_fini(struct objpool_head *oh)
{
	uint32_t i, flags;

	if (!oh->oh_slots)
		return;

	if (!oh->oh_release) {
		__objpool_fini_percpu_slots(oh);
		return;
	}

	/* cleanup all objects remained in objpool */
	for (i = 0; i < oh->oh_ncpus; i++) {
		void *obj;
		do {
			flags = OBJPOOL_FLAG_NODE;
			obj = __objpool_try_get_slot(oh->oh_slots[i]);
			if (!obj)
				break;
			if (!objpool_is_inpool(obj, oh) &&
			    !objpool_is_inslot(obj, oh)) {
				flags |= OBJPOOL_FLAG_USER;
			}
			oh->oh_release(oh->oh_context, obj, flags);
		} while (obj);
	}

	/* release percpu slots */
	__objpool_fini_percpu_slots(oh);

	/* cleanup user private pool and related context */
	flags = OBJPOOL_FLAG_POOL;
	if (oh->oh_pool)
		flags |= OBJPOOL_FLAG_USER;
	oh->oh_release(oh->oh_context, oh->oh_pool, flags);
}
EXPORT_SYMBOL_GPL(objpool_fini);
