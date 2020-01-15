/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _GEN_CNA_LOCK_SLOWPATH
#error "do not include this file"
#endif

#include <linux/topology.h>

/*
 * Implement a NUMA-aware version of MCS (aka CNA, or compact NUMA-aware lock).
 *
 * In CNA, spinning threads are organized in two queues, a main queue for
 * threads running on the same NUMA node as the current lock holder, and a
 * secondary queue for threads running on other nodes. Schematically, it
 * looks like this:
 *
 *    cna_node
 *   +----------+    +--------+        +--------+
 *   |mcs:next  | -> |mcs:next| -> ... |mcs:next| -> NULL      [Main queue]
 *   |mcs:locked| -+ +--------+        +--------+
 *   +----------+  |
 *                 +----------------------+
 *                                        \/
 *                 +--------+         +--------+
 *                 |mcs:next| -> ...  |mcs:next|          [Secondary queue]
 *                 +--------+         +--------+
 *                     ^                    |
 *                     +--------------------+
 *
 * N.B. locked = 1 if secondary queue is absent. Othewrise, it contains the
 * encoded pointer to the tail of the secondary queue, which is organized as a
 * circular list.
 *
 * After acquiring the MCS lock and before acquiring the spinlock, the lock
 * holder scans the main queue looking for a thread running on the same node
 * (pre-scan). If found (call it thread T), all threads in the main queue
 * between the current lock holder and T are moved to the end of the secondary
 * queue.  If such T is not found, we make another scan of the main queue when
 * unlocking the MCS lock (post-scan), starting at the node where pre-scan
 * stopped. If both scans fail to find such T, the MCS lock is passed to the
 * first thread in the secondary queue. If the secondary queue is empty, the
 * lock is passed to the next thread in the main queue.
 *
 * For more details, see https://arxiv.org/abs/1810.05600.
 *
 * Authors: Alex Kogan <alex.kogan@oracle.com>
 *          Dave Dice <dave.dice@oracle.com>
 */

struct cna_node {
	struct mcs_spinlock	mcs;
	int			numa_node;
	u32			encoded_tail;
	u32			pre_scan_result; /* encoded tail or enum val */
	u32			intra_count;
};

enum {
	LOCAL_WAITER_FOUND = 2,	/* 0 and 1 are reserved for @locked */
	FLUSH_SECONDARY_QUEUE = 3,
	MIN_ENCODED_TAIL
};

/*
 * Controls the threshold for the number of intra-node lock hand-offs before
 * the NUMA-aware variant of spinlock is forced to be passed to a thread on
 * another NUMA node. By default, the chosen value provides reasonable
 * long-term fairness without sacrificing performance compared to a lock
 * that does not have any fairness guarantees. The default setting can
 * be changed with the "numa_spinlock_threshold" boot option.
 */
unsigned int intra_node_handoff_threshold __ro_after_init = 1 << 16;

static void __init cna_init_nodes_per_cpu(unsigned int cpu)
{
	struct mcs_spinlock *base = per_cpu_ptr(&qnodes[0].mcs, cpu);
	int numa_node = cpu_to_node(cpu);
	int i;

	for (i = 0; i < MAX_NODES; i++) {
		struct cna_node *cn = (struct cna_node *)grab_mcs_node(base, i);

		cn->numa_node = numa_node;
		cn->encoded_tail = encode_tail(cpu, i);
		/*
		 * make sure @encoded_tail is not confused with other valid
		 * values for @locked (0 or 1) or with designated values for
		 * @pre_scan_result
		 */
		WARN_ON(cn->encoded_tail < MIN_ENCODED_TAIL);
	}
}

static int __init cna_init_nodes(void)
{
	unsigned int cpu;

	/*
	 * this will break on 32bit architectures, so we restrict
	 * the use of CNA to 64bit only (see arch/x86/Kconfig)
	 */
	BUILD_BUG_ON(sizeof(struct cna_node) > sizeof(struct qnode));
	/* we store an ecoded tail word in the node's @locked field */
	BUILD_BUG_ON(sizeof(u32) > sizeof(unsigned int));

	for_each_possible_cpu(cpu)
		cna_init_nodes_per_cpu(cpu);

	return 0;
}
early_initcall(cna_init_nodes);

static __always_inline void cna_init_node(struct mcs_spinlock *node)
{
	((struct cna_node *)node)->intra_count = 0;
}

/* this function is called only when the primary queue is empty */
static inline bool cna_try_change_tail(struct qspinlock *lock, u32 val,
				       struct mcs_spinlock *node)
{
	struct mcs_spinlock *head_2nd, *tail_2nd;
	u32 new;

	/* If the secondary queue is empty, do what MCS does. */
	if (node->locked <= 1)
		return __try_clear_tail(lock, val, node);

	/*
	 * Try to update the tail value to the last node in the secondary queue.
	 * If successful, pass the lock to the first thread in the secondary
	 * queue. Doing those two actions effectively moves all nodes from the
	 * secondary queue into the main one.
	 */
	tail_2nd = decode_tail(node->locked);
	head_2nd = tail_2nd->next;
	new = ((struct cna_node *)tail_2nd)->encoded_tail + _Q_LOCKED_VAL;

	if (atomic_try_cmpxchg_relaxed(&lock->val, &val, new)) {
		/*
		 * Try to reset @next in tail_2nd to NULL, but no need to check
		 * the result - if failed, a new successor has updated it.
		 */
		cmpxchg_relaxed(&tail_2nd->next, head_2nd, NULL);
		arch_mcs_pass_lock(&head_2nd->locked, 1);
		return true;
	}

	return false;
}

/*
 * cna_splice_tail -- splice nodes in the main queue between [first, last]
 * onto the secondary queue.
 */
static void cna_splice_tail(struct mcs_spinlock *node,
			    struct mcs_spinlock *first,
			    struct mcs_spinlock *last)
{
	/* remove [first,last] */
	node->next = last->next;

	/* stick [first,last] on the secondary queue tail */
	if (node->locked <= 1) { /* if secondary queue is empty */
		/* create secondary queue */
		last->next = first;
	} else {
		/* add to the tail of the secondary queue */
		struct mcs_spinlock *tail_2nd = decode_tail(node->locked);
		struct mcs_spinlock *head_2nd = tail_2nd->next;

		tail_2nd->next = first;
		last->next = head_2nd;
	}

	node->locked = ((struct cna_node *)last)->encoded_tail;
}

/*
 * cna_scan_main_queue - scan the main waiting queue looking for the first
 * thread running on the same NUMA node as the lock holder. If found (call it
 * thread T), move all threads in the main queue between the lock holder and
 * T to the end of the secondary queue and return LOCAL_WAITER_FOUND;
 * otherwise, return the encoded pointer of the last scanned node in the
 * primary queue (so a subsequent scan can be resumed from that node).
 *
 * Schematically, this may look like the following (nn stands for numa_node and
 * et stands for encoded_tail).
 *
 *   when cna_scan_main_queue() is called (the secondary queue is empty):
 *
 *  A+------------+   B+--------+   C+--------+   T+--------+
 *   |mcs:next    | -> |mcs:next| -> |mcs:next| -> |mcs:next| -> NULL
 *   |mcs:locked=1|    |cna:nn=0|    |cna:nn=2|    |cna:nn=1|
 *   |cna:nn=1    |    +--------+    +--------+    +--------+
 *   +----------- +
 *
 *   when cna_scan_main_queue() returns (the secondary queue contains B and C):
 *
 *  A+----------------+    T+--------+
 *   |mcs:next        | ->  |mcs:next| -> NULL
 *   |mcs:locked=C.et | -+  |cna:nn=1|
 *   |cna:nn=1        |  |  +--------+
 *   +--------------- +  +-----+
 *                             \/
 *          B+--------+   C+--------+
 *           |mcs:next| -> |mcs:next| -+
 *           |cna:nn=0|    |cna:nn=2|  |
 *           +--------+    +--------+  |
 *               ^                     |
 *               +---------------------+
 *
 * The worst case complexity of the scan is O(n), where n is the number
 * of current waiters. However, the amortized complexity is close to O(1),
 * as the immediate successor is likely to be running on the same node once
 * threads from other nodes are moved to the secondary queue.
 *
 * @node      : Pointer to the MCS node of the lock holder
 * @pred_start: Pointer to the MCS node of the waiter whose successor should be
 *              the first node in the scan
 * Return     : LOCAL_WAITER_FOUND or encoded tail of the last scanned waiter
 */
static u32 cna_scan_main_queue(struct mcs_spinlock *node,
			       struct mcs_spinlock *pred_start)
{
	struct cna_node *cn = (struct cna_node *)node;
	struct cna_node *cni = (struct cna_node *)READ_ONCE(pred_start->next);
	struct cna_node *last;
	int my_numa_node = cn->numa_node;

	/* find any next waiter on 'our' NUMA node */
	for (last = cn;
	     cni && cni->numa_node != my_numa_node;
	     last = cni, cni = (struct cna_node *)READ_ONCE(cni->mcs.next))
		;

	/* if found, splice any skipped waiters onto the secondary queue */
	if (cni) {
		if (last != cn)	/* did we skip any waiters? */
			cna_splice_tail(node, node->next,
					(struct mcs_spinlock *)last);
		return LOCAL_WAITER_FOUND;
	}

	return last->encoded_tail;
}

__always_inline u32 cna_pre_scan(struct qspinlock *lock,
				  struct mcs_spinlock *node)
{
	struct cna_node *cn = (struct cna_node *)node;

	cn->pre_scan_result =
		cn->intra_count == intra_node_handoff_threshold ?
			FLUSH_SECONDARY_QUEUE : cna_scan_main_queue(node, node);

	return 0;
}

static inline void cna_pass_lock(struct mcs_spinlock *node,
				 struct mcs_spinlock *next)
{
	struct cna_node *cn = (struct cna_node *)node;
	struct mcs_spinlock *next_holder = next, *tail_2nd;
	u32 val = 1;

	u32 scan = cn->pre_scan_result;

	/*
	 * check if a successor from the same numa node has not been found in
	 * pre-scan, and if so, try to find it in post-scan starting from the
	 * node where pre-scan stopped (stored in @pre_scan_result)
	 */
	if (scan >= MIN_ENCODED_TAIL)
		scan = cna_scan_main_queue(node, decode_tail(scan));

	if (scan == LOCAL_WAITER_FOUND) {
		next_holder = node->next;
		/*
		 * we unlock successor by passing a non-zero value,
		 * so set @val to 1 iff @locked is 0, which will happen
		 * if we acquired the MCS lock when its queue was empty
		 */
		val = node->locked ? node->locked : 1;
		/* inc @intra_count if the secondary queue is not empty */
		((struct cna_node *)next_holder)->intra_count =
			cn->intra_count + (node->locked > 1);
	} else if (node->locked > 1) {	  /* if secondary queue is not empty */
		/* next holder will be the first node in the secondary queue */
		tail_2nd = decode_tail(node->locked);
		/* @tail_2nd->next points to the head of the secondary queue */
		next_holder = tail_2nd->next;
		/* splice the secondary queue onto the head of the main queue */
		tail_2nd->next = next;
	}

	arch_mcs_pass_lock(&next_holder->locked, val);
}

/*
 * Constant (boot-param configurable) flag selecting the NUMA-aware variant
 * of spinlock.  Possible values: -1 (off) / 0 (auto, default) / 1 (on).
 */
static int numa_spinlock_flag;

static int __init numa_spinlock_setup(char *str)
{
	if (!strcmp(str, "auto")) {
		numa_spinlock_flag = 0;
		return 1;
	} else if (!strcmp(str, "on")) {
		numa_spinlock_flag = 1;
		return 1;
	} else if (!strcmp(str, "off")) {
		numa_spinlock_flag = -1;
		return 1;
	}

	return 0;
}
__setup("numa_spinlock=", numa_spinlock_setup);

void __cna_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);

/*
 * Switch to the NUMA-friendly slow path for spinlocks when we have
 * multiple NUMA nodes in native environment, unless the user has
 * overridden this default behavior by setting the numa_spinlock flag.
 */
void __init cna_configure_spin_lock_slowpath(void)
{
	if ((numa_spinlock_flag == 1) ||
	    (numa_spinlock_flag == 0 && nr_node_ids > 1 &&
		    pv_ops.lock.queued_spin_lock_slowpath ==
			native_queued_spin_lock_slowpath)) {
		pv_ops.lock.queued_spin_lock_slowpath =
		    __cna_queued_spin_lock_slowpath;

		pr_info("Enabling CNA spinlock\n");
	}
}

static int __init numa_spinlock_threshold_setup(char *str)
{
	int new_threshold_param;

	if (get_option(&str, &new_threshold_param)) {
		/* valid value is between 0 and 31 */
		if (new_threshold_param < 0 || new_threshold_param > 31)
			return 0;

		intra_node_handoff_threshold = 1 << new_threshold_param;
		return 1;
	}

	return 0;
}
__setup("numa_spinlock_threshold=", numa_spinlock_threshold_setup);
