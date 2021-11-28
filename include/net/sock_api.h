/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _SOCK_API_H
#define _SOCK_API_H

#include <net/sock_types.h>

#include <net/net_namespace_types.h>
#include <linux/uio_api.h>
#include <linux/mutex_api.h>
#include <linux/sched/types.h>
#include <linux/smp_api.h>
#include <linux/net.h>
#include <linux/ratelimit.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/bitops.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>	/* struct sk_buff */
#include <linux/mm.h>
#include <linux/debug_locks.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/page_counter.h>
#include <linux/static_key.h>
#include <linux/wait_types.h>
#include <linux/cgroup_types.h>
#include <linux/rbtree.h>
#include <linux/prandom.h>
#include <linux/rculist_nulls.h>
#include <linux/sockptr.h>
#include <linux/indirect_call_wrapper.h>
#include <linux/atomic.h>
#include <linux/refcount.h>
#include <net/dst.h>
#include <net/checksum.h>
#include <net/tcp_states.h>
#include <linux/percpu_counter.h>
#include <linux/net_tstamp.h>

#include <linux/spinlock_api.h>
#include <linux/skbuff_api.h>
#include <linux/lockdep_api.h>

#if BITS_PER_LONG==32
#include <linux/seqlock_api.h>
#endif

/* Pointer stored in sk_user_data might not be suitable for copying
 * when cloning the socket. For instance, it can point to a reference
 * counted object. sk_user_data bottom bit is set if pointer must not
 * be copied.
 */
#define SK_USER_DATA_NOCOPY	1UL
#define SK_USER_DATA_BPF	2UL	/* Managed by BPF */
#define SK_USER_DATA_PTRMASK	~(SK_USER_DATA_NOCOPY | SK_USER_DATA_BPF)

/**
 * sk_user_data_is_nocopy - Test if sk_user_data pointer must not be copied
 * @sk: socket
 */
static inline bool sk_user_data_is_nocopy(const struct sock *sk)
{
	return ((uintptr_t)sk->sk_user_data & SK_USER_DATA_NOCOPY);
}

#define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))

#define rcu_dereference_sk_user_data(sk)				\
({									\
	void *__tmp = rcu_dereference(__sk_user_data((sk)));		\
	(void *)((uintptr_t)__tmp & SK_USER_DATA_PTRMASK);		\
})
#define rcu_assign_sk_user_data(sk, ptr)				\
({									\
	uintptr_t __tmp = (uintptr_t)(ptr);				\
	WARN_ON_ONCE(__tmp & ~SK_USER_DATA_PTRMASK);			\
	rcu_assign_pointer(__sk_user_data((sk)), __tmp);		\
})
#define rcu_assign_sk_user_data_nocopy(sk, ptr)				\
({									\
	uintptr_t __tmp = (uintptr_t)(ptr);				\
	WARN_ON_ONCE(__tmp & ~SK_USER_DATA_PTRMASK);			\
	rcu_assign_pointer(__sk_user_data((sk)),			\
			   __tmp | SK_USER_DATA_NOCOPY);		\
})

/*
 * SK_CAN_REUSE and SK_NO_REUSE on a socket mean that the socket is OK
 * or not whether his port will be reused by someone else. SK_FORCE_REUSE
 * on a socket means that the socket will reuse everybody else's port
 * without looking at the other's sk_reuse value.
 */

#define SK_NO_REUSE	0
#define SK_CAN_REUSE	1
#define SK_FORCE_REUSE	2

int sk_set_peek_off(struct sock *sk, int val);

static inline int sk_peek_offset(struct sock *sk, int flags)
{
	if (unlikely(flags & MSG_PEEK)) {
		return READ_ONCE(sk->sk_peek_off);
	}

	return 0;
}

static inline void sk_peek_offset_bwd(struct sock *sk, int val)
{
	s32 off = READ_ONCE(sk->sk_peek_off);

	if (unlikely(off >= 0)) {
		off = max_t(s32, off - val, 0);
		WRITE_ONCE(sk->sk_peek_off, off);
	}
}

static inline void sk_peek_offset_fwd(struct sock *sk, int val)
{
	sk_peek_offset_bwd(sk, -val);
}

/*
 * Hashed lists helper routines
 */
static inline struct sock *sk_entry(const struct hlist_node *node)
{
	return hlist_entry(node, struct sock, sk_node);
}

static inline struct sock *__sk_head(const struct hlist_head *head)
{
	return hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(const struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *__sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_entry(head->first, struct sock, sk_nulls_node);
}

static inline struct sock *sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_empty(head) ? NULL : __sk_nulls_head(head);
}

static inline struct sock *sk_next(const struct sock *sk)
{
	return hlist_entry_safe(sk->sk_node.next, struct sock, sk_node);
}

static inline struct sock *sk_nulls_next(const struct sock *sk)
{
	return (!is_a_nulls(sk->sk_nulls_node.next)) ?
		hlist_nulls_entry(sk->sk_nulls_node.next,
				  struct sock, sk_nulls_node) :
		NULL;
}

static inline bool sk_unhashed(const struct sock *sk)
{
	return hlist_unhashed(&sk->sk_node);
}

static inline bool sk_hashed(const struct sock *sk)
{
	return !sk_unhashed(sk);
}

static inline void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static inline void sk_nulls_node_init(struct hlist_nulls_node *node)
{
	node->pprev = NULL;
}

static inline void __sk_del_node(struct sock *sk)
{
	__hlist_del(&sk->sk_node);
}

/* NB: equivalent to hlist_del_init_rcu */
static inline bool __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return true;
	}
	return false;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static __always_inline void sock_hold(struct sock *sk)
{
	refcount_inc(&sk->sk_refcnt);
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static __always_inline void __sock_put(struct sock *sk)
{
	refcount_dec(&sk->sk_refcnt);
}

static inline bool sk_del_node_init(struct sock *sk)
{
	bool rc = __sk_del_node_init(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(refcount_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}
#define sk_del_node_init_rcu(sk)	sk_del_node_init(sk)

static inline bool __sk_nulls_del_node_init_rcu(struct sock *sk)
{
	if (sk_hashed(sk)) {
		hlist_nulls_del_init_rcu(&sk->sk_nulls_node);
		return true;
	}
	return false;
}

static inline bool sk_nulls_del_node_init_rcu(struct sock *sk)
{
	bool rc = __sk_nulls_del_node_init_rcu(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(refcount_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}

static inline void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&sk->sk_node, list);
}

static inline void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

static inline void sk_add_node_rcu(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	if (IS_ENABLED(CONFIG_IPV6) && sk->sk_reuseport &&
	    sk->sk_family == AF_INET6)
		hlist_add_tail_rcu(&sk->sk_node, list);
	else
		hlist_add_head_rcu(&sk->sk_node, list);
}

static inline void sk_add_node_tail_rcu(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	hlist_add_tail_rcu(&sk->sk_node, list);
}

static inline void __sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	hlist_nulls_add_head_rcu(&sk->sk_nulls_node, list);
}

static inline void __sk_nulls_add_node_tail_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	hlist_nulls_add_tail_rcu(&sk->sk_nulls_node, list);
}

static inline void sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	sock_hold(sk);
	__sk_nulls_add_node_rcu(sk, list);
}

static inline void __sk_del_bind_node(struct sock *sk)
{
	__hlist_del(&sk->sk_bind_node);
}

static inline void sk_add_bind_node(struct sock *sk,
					struct hlist_head *list)
{
	hlist_add_head(&sk->sk_bind_node, list);
}

#define sk_for_each(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_node)
#define sk_for_each_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, sk_node)
#define sk_nulls_for_each(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, sk_nulls_node)
#define sk_nulls_for_each_rcu(__sk, node, list) \
	hlist_nulls_for_each_entry_rcu(__sk, node, list, sk_nulls_node)
#define sk_for_each_from(__sk) \
	hlist_for_each_entry_from(__sk, sk_node)
#define sk_nulls_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_nulls_node; 1; })) \
		hlist_nulls_for_each_entry_from(__sk, node, sk_nulls_node)
#define sk_for_each_safe(__sk, tmp, list) \
	hlist_for_each_entry_safe(__sk, tmp, list, sk_node)
#define sk_for_each_bound(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_bind_node)

/**
 * sk_for_each_entry_offset_rcu - iterate over a list at a given struct offset
 * @tpos:	the type * to use as a loop cursor.
 * @pos:	the &struct hlist_node to use as a loop cursor.
 * @head:	the head for your list.
 * @offset:	offset of hlist_node within the struct.
 *
 */
#define sk_for_each_entry_offset_rcu(tpos, pos, head, offset)		       \
	for (pos = rcu_dereference(hlist_first_rcu(head));		       \
	     pos != NULL &&						       \
		({ tpos = (typeof(*tpos) *)((void *)pos - offset); 1;});       \
	     pos = rcu_dereference(hlist_next_rcu(pos)))

extern struct user_namespace *sk_user_ns(struct sock *sk);

/* Sock flags */
enum sock_flags {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	SOCK_DBG, /* %SO_DEBUG setting */
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	SOCK_RCVTSTAMPNS, /* %SO_TIMESTAMPNS setting */
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	SOCK_MEMALLOC, /* VM depends on this socket for swapping */
	SOCK_TIMESTAMPING_RX_SOFTWARE,  /* %SOF_TIMESTAMPING_RX_SOFTWARE */
	SOCK_FASYNC, /* fasync() active */
	SOCK_RXQ_OVFL,
	SOCK_ZEROCOPY, /* buffers from userspace */
	SOCK_WIFI_STATUS, /* push wifi status to userspace */
	SOCK_NOFCS, /* Tell NIC not to do the Ethernet FCS.
		     * Will use last 4 bytes of packet sent from
		     * user-space instead.
		     */
	SOCK_FILTER_LOCKED, /* Filter cannot be changed anymore */
	SOCK_SELECT_ERR_QUEUE, /* Wake select on error queue */
	SOCK_RCU_FREE, /* wait rcu grace period in sk_destruct() */
	SOCK_TXTIME,
	SOCK_XDP, /* XDP is attached */
	SOCK_TSTAMP_NEW, /* Indicates 64 bit timestamps always */
};

#define SK_FLAGS_TIMESTAMP ((1UL << SOCK_TIMESTAMP) | (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE))

static inline void sock_copy_flags(struct sock *nsk, struct sock *osk)
{
	nsk->sk_flags = osk->sk_flags;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline void sock_valbool_flag(struct sock *sk, enum sock_flags bit,
				     int valbool)
{
	if (valbool)
		sock_set_flag(sk, bit);
	else
		sock_reset_flag(sk, bit);
}

static inline bool sock_flag(const struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}

#ifdef CONFIG_NET
DECLARE_STATIC_KEY_FALSE(memalloc_socks_key);
static inline int sk_memalloc_socks(void)
{
	return static_branch_unlikely(&memalloc_socks_key);
}

void __receive_sock(struct file *file);
#else

static inline int sk_memalloc_socks(void)
{
	return 0;
}

static inline void __receive_sock(struct file *file)
{ }
#endif

static inline gfp_t sk_gfp_mask(const struct sock *sk, gfp_t gfp_mask)
{
	return gfp_mask | (sk->sk_allocation & __GFP_MEMALLOC);
}

static inline void sk_acceptq_removed(struct sock *sk)
{
	WRITE_ONCE(sk->sk_ack_backlog, sk->sk_ack_backlog - 1);
}

static inline void sk_acceptq_added(struct sock *sk)
{
	WRITE_ONCE(sk->sk_ack_backlog, sk->sk_ack_backlog + 1);
}

/* Note: If you think the test should be:
 *	return READ_ONCE(sk->sk_ack_backlog) >= READ_ONCE(sk->sk_max_ack_backlog);
 * Then please take a look at commit 64a146513f8f ("[NET]: Revert incorrect accept queue backlog changes.")
 */
static inline bool sk_acceptq_is_full(const struct sock *sk)
{
	return READ_ONCE(sk->sk_ack_backlog) > READ_ONCE(sk->sk_max_ack_backlog);
}

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(const struct sock *sk)
{
	return READ_ONCE(sk->sk_wmem_queued) >> 1;
}

static inline int sk_stream_wspace(const struct sock *sk)
{
	return READ_ONCE(sk->sk_sndbuf) - READ_ONCE(sk->sk_wmem_queued);
}

static inline void sk_wmem_queued_add(struct sock *sk, int val)
{
	WRITE_ONCE(sk->sk_wmem_queued, sk->sk_wmem_queued + val);
}

void sk_stream_write_space(struct sock *sk);

static inline void sk_incoming_cpu_update(struct sock *sk)
{
	int cpu = raw_smp_processor_id();

	if (unlikely(READ_ONCE(sk->sk_incoming_cpu) != cpu))
		WRITE_ONCE(sk->sk_incoming_cpu, cpu);
}

static inline void sock_rps_save_rxhash(struct sock *sk,
					const struct sk_buff *skb)
{
#ifdef CONFIG_RPS
	if (unlikely(sk->sk_rxhash != skb->hash))
		sk->sk_rxhash = skb->hash;
#endif
}

static inline void sock_rps_reset_rxhash(struct sock *sk)
{
#ifdef CONFIG_RPS
	sk->sk_rxhash = 0;
#endif
}

#define sk_wait_event(__sk, __timeo, __condition, __wait)		\
	({	int __rc;						\
		release_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = wait_woken(__wait,			\
						TASK_INTERRUPTIBLE,	\
						*(__timeo));		\
		}							\
		sched_annotate_sleep();					\
		lock_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})

int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
void sk_stream_wait_close(struct sock *sk, long timeo_p);
int sk_stream_error(struct sock *sk, int flags, int err);
void sk_stream_kill_queues(struct sock *sk);
void sk_set_memalloc(struct sock *sk);
void sk_clear_memalloc(struct sock *sk);

void __sk_flush_backlog(struct sock *sk);

static inline bool sk_flush_backlog(struct sock *sk)
{
	if (unlikely(READ_ONCE(sk->sk_backlog.tail))) {
		__sk_flush_backlog(sk);
		return true;
	}
	return false;
}

int sk_wait_data(struct sock *sk, long *timeo, const struct sk_buff *skb);

struct request_sock_ops;
struct timewait_sock_ops;
struct inet_hashinfo;
struct raw_hashinfo;
struct smc_hashinfo;
struct module;
struct sk_psock;

/*
 * caches using SLAB_TYPESAFE_BY_RCU should let .next pointer from nulls nodes
 * un-modified. Special care is taken when initializing object to zero.
 */
static inline void sk_prot_clear_nulls(struct sock *sk, int size)
{
	if (offsetof(struct sock, sk_node.next) != 0)
		memset(sk, 0, offsetof(struct sock, sk_node.next));
	memset(&sk->sk_node.pprev, 0,
	       size - offsetof(struct sock, sk_node.pprev));
}

int proto_register(struct proto *prot, int alloc_slab);
void proto_unregister(struct proto *prot);
int sock_load_diag_module(int family, int protocol);

#ifdef SOCK_REFCNT_DEBUG
static inline void sk_refcnt_debug_inc(struct sock *sk)
{
	atomic_inc(&sk->sk_prot->socks);
}

static inline void sk_refcnt_debug_dec(struct sock *sk)
{
	atomic_dec(&sk->sk_prot->socks);
	printk(KERN_DEBUG "%s socket %p released, %d are still alive\n",
	       sk->sk_prot->name, sk, atomic_read(&sk->sk_prot->socks));
}

static inline void sk_refcnt_debug_release(const struct sock *sk)
{
	if (refcount_read(&sk->sk_refcnt) != 1)
		printk(KERN_DEBUG "Destruction of the %s socket %p delayed, refcnt=%d\n",
		       sk->sk_prot->name, sk, refcount_read(&sk->sk_refcnt));
}
#else /* SOCK_REFCNT_DEBUG */
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#endif /* SOCK_REFCNT_DEBUG */

INDIRECT_CALLABLE_DECLARE(bool tcp_stream_memory_free(const struct sock *sk, int wake));

static inline int sk_forward_alloc_get(const struct sock *sk)
{
#if IS_ENABLED(CONFIG_MPTCP)
	if (sk->sk_prot->forward_alloc_get)
		return sk->sk_prot->forward_alloc_get(sk);
#endif
	return sk->sk_forward_alloc;
}

static inline bool __sk_stream_memory_free(const struct sock *sk, int wake)
{
	if (READ_ONCE(sk->sk_wmem_queued) >= READ_ONCE(sk->sk_sndbuf))
		return false;

	return sk->sk_prot->stream_memory_free ?
		INDIRECT_CALL_INET_1(sk->sk_prot->stream_memory_free,
				     tcp_stream_memory_free, sk, wake) : true;
}

static inline bool sk_stream_memory_free(const struct sock *sk)
{
	return __sk_stream_memory_free(sk, 0);
}

static inline bool __sk_stream_is_writeable(const struct sock *sk, int wake)
{
	return sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) &&
	       __sk_stream_memory_free(sk, wake);
}

static inline bool sk_stream_is_writeable(const struct sock *sk)
{
	return __sk_stream_is_writeable(sk, 0);
}

static inline bool sk_has_memory_pressure(const struct sock *sk)
{
	return sk->sk_prot->memory_pressure != NULL;
}

extern bool sk_under_memory_pressure(const struct sock *sk);

static inline long
sk_memory_allocated(const struct sock *sk)
{
	return atomic_long_read(sk->sk_prot->memory_allocated);
}

static inline long
sk_memory_allocated_add(struct sock *sk, int amt)
{
	return atomic_long_add_return(amt, sk->sk_prot->memory_allocated);
}

static inline void
sk_memory_allocated_sub(struct sock *sk, int amt)
{
	atomic_long_sub(amt, sk->sk_prot->memory_allocated);
}

static inline long
proto_memory_allocated(struct proto *prot)
{
	return atomic_long_read(prot->memory_allocated);
}

static inline bool
proto_memory_pressure(struct proto *prot)
{
	if (!prot->memory_pressure)
		return false;
	return !!*prot->memory_pressure;
}


#ifdef CONFIG_PROC_FS
#define PROTO_INUSE_NR	64	/* should be enough for the first time */
struct prot_inuse {
	int all;
	int val[PROTO_INUSE_NR];
};

static inline void sock_prot_inuse_add(const struct net *net,
				       const struct proto *prot, int val)
{
	this_cpu_add(net->core.prot_inuse->val[prot->inuse_idx], val);
}

static inline void sock_inuse_add(const struct net *net, int val)
{
	this_cpu_add(net->core.prot_inuse->all, val);
}

int sock_prot_inuse_get(struct net *net, struct proto *proto);
int sock_inuse_get(struct net *net);
#else
static inline void sock_prot_inuse_add(const struct net *net,
				       const struct proto *prot, int val)
{
}

static inline void sock_inuse_add(const struct net *net, int val)
{
}
#endif


/* With per-bucket locks this operation is not-atomic, so that
 * this version is not worse.
 */
static inline int __sk_prot_rehash(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	return sk->sk_prot->hash(sk);
}

/* About 10 seconds */
#define SOCK_DESTROY_TIME (10*HZ)

/*
 * Functions for memory accounting
 */
int __sk_mem_raise_allocated(struct sock *sk, int size, int amt, int kind);
int __sk_mem_schedule(struct sock *sk, int size, int kind);
void __sk_mem_reduce_allocated(struct sock *sk, int amount);
void __sk_mem_reclaim(struct sock *sk, int amount);

/* We used to have PAGE_SIZE here, but systems with 64KB pages
 * do not necessarily have 16x time more memory than 4KB ones.
 */
#define SK_MEM_QUANTUM 4096
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SK_MEM_SEND	0
#define SK_MEM_RECV	1

/* sysctl_mem values are in pages, we convert them in SK_MEM_QUANTUM units */
static inline long sk_prot_mem_limits(const struct sock *sk, int index)
{
	long val = sk->sk_prot->sysctl_mem[index];

#if PAGE_SIZE > SK_MEM_QUANTUM
	val <<= PAGE_SHIFT - SK_MEM_QUANTUM_SHIFT;
#elif PAGE_SIZE < SK_MEM_QUANTUM
	val >>= SK_MEM_QUANTUM_SHIFT - PAGE_SHIFT;
#endif
	return val;
}

static inline int sk_mem_pages(int amt)
{
	return (amt + SK_MEM_QUANTUM - 1) >> SK_MEM_QUANTUM_SHIFT;
}

static inline bool sk_has_account(struct sock *sk)
{
	/* return true if protocol supports memory accounting */
	return !!sk->sk_prot->memory_allocated;
}

static inline bool sk_wmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return true;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_SEND);
}

static inline bool
sk_rmem_schedule(struct sock *sk, struct sk_buff *skb, int size)
{
	if (!sk_has_account(sk))
		return true;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_RECV) ||
		skb_pfmemalloc(skb);
}

static inline int sk_unused_reserved_mem(const struct sock *sk)
{
	int unused_mem;

	if (likely(!sk->sk_reserved_mem))
		return 0;

	unused_mem = sk->sk_reserved_mem - sk->sk_wmem_queued -
			atomic_read(&sk->sk_rmem_alloc);

	return unused_mem > 0 ? unused_mem : 0;
}

static inline void sk_mem_reclaim(struct sock *sk)
{
	int reclaimable;

	if (!sk_has_account(sk))
		return;

	reclaimable = sk->sk_forward_alloc - sk_unused_reserved_mem(sk);

	if (reclaimable >= SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk, reclaimable);
}

static inline void sk_mem_reclaim_final(struct sock *sk)
{
	sk->sk_reserved_mem = 0;
	sk_mem_reclaim(sk);
}

static inline void sk_mem_reclaim_partial(struct sock *sk)
{
	int reclaimable;

	if (!sk_has_account(sk))
		return;

	reclaimable = sk->sk_forward_alloc - sk_unused_reserved_mem(sk);

	if (reclaimable > SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk, reclaimable - 1);
}

static inline void sk_mem_charge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc -= size;
}

/* the following macros control memory reclaiming in sk_mem_uncharge()
 */
#define SK_RECLAIM_THRESHOLD	(1 << 21)
#define SK_RECLAIM_CHUNK	(1 << 20)

static inline void sk_mem_uncharge(struct sock *sk, int size)
{
	int reclaimable;

	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc += size;
	reclaimable = sk->sk_forward_alloc - sk_unused_reserved_mem(sk);

	/* Avoid a possible overflow.
	 * TCP send queues can make this happen, if sk_mem_reclaim()
	 * is not called and more than 2 GBytes are released at once.
	 *
	 * If we reach 2 MBytes, reclaim 1 MBytes right now, there is
	 * no need to hold that much forward allocation anyway.
	 */
	if (unlikely(reclaimable >= SK_RECLAIM_THRESHOLD))
		__sk_mem_reclaim(sk, SK_RECLAIM_CHUNK);
}

/*
 * Macro so as to not evaluate some arguments when
 * lockdep is not enabled.
 *
 * Mark both the sk_lock and the sk_lock.slock as a
 * per-address-family lock class.
 */
#define sock_lock_init_class_and_name(sk, sname, skey, name, key)	\
do {									\
	sk->sk_lock.owned = 0;						\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
				(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)

static inline bool lockdep_sock_is_held(const struct sock *sk)
{
	return lockdep_is_held(&sk->sk_lock) ||
	       lockdep_is_held(&sk->sk_lock.slock);
}

void lock_sock_nested(struct sock *sk, int subclass);

static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
}

void __lock_sock(struct sock *sk);
void __release_sock(struct sock *sk);
void release_sock(struct sock *sk);

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))

bool __lock_sock_fast(struct sock *sk) __acquires(&sk->sk_lock.slock);

/**
 * lock_sock_fast - fast version of lock_sock
 * @sk: socket
 *
 * This version should be used for very small section, where process wont block
 * return false if fast path is taken:
 *
 *   sk_lock.slock locked, owned = 0, BH disabled
 *
 * return true if slow path is taken:
 *
 *   sk_lock.slock unlocked, owned = 1, BH enabled
 */
static inline bool lock_sock_fast(struct sock *sk)
{
	/* The sk_lock has mutex_lock() semantics here. */
	mutex_acquire(&sk->sk_lock.dep_map, 0, 0, _RET_IP_);

	return __lock_sock_fast(sk);
}

/* fast socket lock variant for caller already holding a [different] socket lock */
static inline bool lock_sock_fast_nested(struct sock *sk)
{
	mutex_acquire(&sk->sk_lock.dep_map, SINGLE_DEPTH_NESTING, 0, _RET_IP_);

	return __lock_sock_fast(sk);
}

/**
 * unlock_sock_fast - complement of lock_sock_fast
 * @sk: socket
 * @slow: slow mode
 *
 * fast unlock socket for user context.
 * If slow mode is on, we call regular release_sock()
 */
static inline void unlock_sock_fast(struct sock *sk, bool slow)
	__releases(&sk->sk_lock.slock)
{
	if (slow) {
		release_sock(sk);
		__release(&sk->sk_lock.slock);
	} else {
		mutex_release(&sk->sk_lock.dep_map, _RET_IP_);
		spin_unlock_bh(&sk->sk_lock.slock);
	}
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */

static inline void sock_owned_by_me(const struct sock *sk)
{
#ifdef CONFIG_LOCKDEP
	WARN_ON_ONCE(!lockdep_sock_is_held(sk) && debug_locks);
#endif
}

static inline bool sock_owned_by_user(const struct sock *sk)
{
	sock_owned_by_me(sk);
	return sk->sk_lock.owned;
}

static inline bool sock_owned_by_user_nocheck(const struct sock *sk)
{
	return sk->sk_lock.owned;
}

static inline void sock_release_ownership(struct sock *sk)
{
	if (sock_owned_by_user_nocheck(sk)) {
		sk->sk_lock.owned = 0;

		/* The sk_lock has mutex_unlock() semantics: */
		mutex_release(&sk->sk_lock.dep_map, _RET_IP_);
	}
}

/* no reclassification while locks are held */
static inline bool sock_allow_reclassification(const struct sock *csk)
{
	struct sock *sk = (struct sock *)csk;

	return !sock_owned_by_user_nocheck(sk) &&
		!spin_is_locked(&sk->sk_lock.slock);
}

struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
		      struct proto *prot, int kern);
void sk_free(struct sock *sk);
void sk_destruct(struct sock *sk);
struct sock *sk_clone_lock(const struct sock *sk, const gfp_t priority);
void sk_free_unlock_clone(struct sock *sk);

struct sk_buff *sock_wmalloc(struct sock *sk, unsigned long size, int force,
			     gfp_t priority);
void __sock_wfree(struct sk_buff *skb);
void sock_wfree(struct sk_buff *skb);
struct sk_buff *sock_omalloc(struct sock *sk, unsigned long size,
			     gfp_t priority);
void skb_orphan_partial(struct sk_buff *skb);
void sock_rfree(struct sk_buff *skb);
void sock_efree(struct sk_buff *skb);
#ifdef CONFIG_INET
void sock_edemux(struct sk_buff *skb);
void sock_pfree(struct sk_buff *skb);
#else
#define sock_edemux sock_efree
#endif

int sock_setsockopt(struct socket *sock, int level, int op,
		    sockptr_t optval, unsigned int optlen);

int sock_getsockopt(struct socket *sock, int level, int op,
		    char __user *optval, int __user *optlen);
int sock_gettstamp(struct socket *sock, void __user *userstamp,
		   bool timeval, bool time32);
struct sk_buff *sock_alloc_send_skb(struct sock *sk, unsigned long size,
				    int noblock, int *errcode);
struct sk_buff *sock_alloc_send_pskb(struct sock *sk, unsigned long header_len,
				     unsigned long data_len, int noblock,
				     int *errcode, int max_page_order);
void *sock_kmalloc(struct sock *sk, int size, gfp_t priority);
void sock_kfree_s(struct sock *sk, void *mem, int size);
void sock_kzfree_s(struct sock *sk, void *mem, int size);
void sk_send_sigurg(struct sock *sk);

static inline void sockcm_init(struct sockcm_cookie *sockc,
			       const struct sock *sk)
{
	*sockc = (struct sockcm_cookie) { .tsflags = sk->sk_tsflags };
}

int __sock_cmsg_send(struct sock *sk, struct msghdr *msg, struct cmsghdr *cmsg,
		     struct sockcm_cookie *sockc);
int sock_cmsg_send(struct sock *sk, struct msghdr *msg,
		   struct sockcm_cookie *sockc);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * does not implement a particular function.
 */
int sock_no_bind(struct socket *, struct sockaddr *, int);
int sock_no_connect(struct socket *, struct sockaddr *, int, int);
int sock_no_socketpair(struct socket *, struct socket *);
int sock_no_accept(struct socket *, struct socket *, int, bool);
int sock_no_getname(struct socket *, struct sockaddr *, int);
int sock_no_ioctl(struct socket *, unsigned int, unsigned long);
int sock_no_listen(struct socket *, int);
int sock_no_shutdown(struct socket *, int);
int sock_no_sendmsg(struct socket *, struct msghdr *, size_t);
int sock_no_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t len);
int sock_no_recvmsg(struct socket *, struct msghdr *, size_t, int);
int sock_no_mmap(struct file *file, struct socket *sock,
		 struct vm_area_struct *vma);
ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset,
			 size_t size, int flags);
ssize_t sock_no_sendpage_locked(struct sock *sk, struct page *page,
				int offset, size_t size, int flags);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * uses the inet style.
 */
int sock_common_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen);
int sock_common_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			int flags);
int sock_common_setsockopt(struct socket *sock, int level, int optname,
			   sockptr_t optval, unsigned int optlen);

void sk_common_release(struct sock *sk);

/*
 *	Default socket callbacks and setup code
 */

/* Initialise core socket variables */
void sock_init_data(struct socket *sock, struct sock *sk);

/*
 * Socket reference counting postulates.
 *
 * * Each user of socket SHOULD hold a reference count.
 * * Each access point to socket (an hash table bucket, reference from a list,
 *   running timer, skb in flight MUST hold a reference count.
 * * When reference count hits 0, it means it will never increase back.
 * * When reference count hits 0, it means that no references from
 *   outside exist to this socket and current process on current CPU
 *   is last user and may/should destroy this socket.
 * * sk_free is called from any context: process, BH, IRQ. When
 *   it is called, socket has no references from outside -> sk_free
 *   may release descendant resources allocated by the socket, but
 *   to the time when it is called, socket is NOT referenced by any
 *   hash tables, lists etc.
 * * Packets, delivered from outside (from network or from another process)
 *   and enqueued on receive/error queues SHOULD NOT grab reference count,
 *   when they sit in queue. Otherwise, packets will leak to hole, when
 *   socket is looked up by one cpu and unhasing is made by another CPU.
 *   It is true for udp/raw, netlink (leak to receive and error queues), tcp
 *   (leak to backlog). Packet socket does all the processing inside
 *   BR_NETPROTO_LOCK, so that it has not this race condition. UNIX sockets
 *   use separate SMP lock, so that they are prone too.
 */

/* Ungrab socket and destroy it, if it was the last reference. */
static inline void sock_put(struct sock *sk)
{
	if (refcount_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}
/* Generic version of sock_put(), dealing with all sockets
 * (TCP_TIMEWAIT, TCP_NEW_SYN_RECV, ESTABLISHED...)
 */
void sock_gen_put(struct sock *sk);

int __sk_receive_skb(struct sock *sk, struct sk_buff *skb, const int nested,
		     unsigned int trim_cap, bool refcounted);
static inline int sk_receive_skb(struct sock *sk, struct sk_buff *skb,
				 const int nested)
{
	return __sk_receive_skb(sk, skb, nested, 1, true);
}

static inline void sk_tx_queue_set(struct sock *sk, int tx_queue)
{
	/* sk_tx_queue_mapping accept only upto a 16-bit value */
	if (WARN_ON_ONCE((unsigned short)tx_queue >= USHRT_MAX))
		return;
	sk->sk_tx_queue_mapping = tx_queue;
}

#define NO_QUEUE_MAPPING	USHRT_MAX

static inline void sk_tx_queue_clear(struct sock *sk)
{
	sk->sk_tx_queue_mapping = NO_QUEUE_MAPPING;
}

static inline int sk_tx_queue_get(const struct sock *sk)
{
	if (sk && sk->sk_tx_queue_mapping != NO_QUEUE_MAPPING)
		return sk->sk_tx_queue_mapping;

	return -1;
}

static inline void __sk_rx_queue_set(struct sock *sk,
				     const struct sk_buff *skb,
				     bool force_set)
{
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
	if (skb_rx_queue_recorded(skb)) {
		u16 rx_queue = skb_get_rx_queue(skb);

		if (force_set ||
		    unlikely(READ_ONCE(sk->sk_rx_queue_mapping) != rx_queue))
			WRITE_ONCE(sk->sk_rx_queue_mapping, rx_queue);
	}
#endif
}

static inline void sk_rx_queue_set(struct sock *sk, const struct sk_buff *skb)
{
	__sk_rx_queue_set(sk, skb, true);
}

static inline void sk_rx_queue_update(struct sock *sk, const struct sk_buff *skb)
{
	__sk_rx_queue_set(sk, skb, false);
}

static inline void sk_rx_queue_clear(struct sock *sk)
{
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
	WRITE_ONCE(sk->sk_rx_queue_mapping, NO_QUEUE_MAPPING);
#endif
}

static inline int sk_rx_queue_get(const struct sock *sk)
{
#ifdef CONFIG_SOCK_RX_QUEUE_MAPPING
	if (sk) {
		int res = READ_ONCE(sk->sk_rx_queue_mapping);

		if (res != NO_QUEUE_MAPPING)
			return res;
	}
#endif

	return -1;
}

static inline void sk_set_socket(struct sock *sk, struct socket *sock)
{
	sk->sk_socket = sock;
}

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	BUILD_BUG_ON(offsetof(struct socket_wq, wait) != 0);
	return &rcu_dereference_raw(sk->sk_wq)->wait;
}
/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 */
static inline void sock_orphan(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk_set_socket(sk, NULL);
	sk->sk_wq  = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

extern void sock_graft(struct sock *sk, struct socket *parent);

kuid_t sock_i_uid(struct sock *sk);
unsigned long sock_i_ino(struct sock *sk);

static inline kuid_t sock_net_uid(const struct net *net, const struct sock *sk)
{
	return sk ? sk->sk_uid : make_kuid(net->user_ns, 0);
}

static inline u32 net_tx_rndhash(void)
{
	u32 v = prandom_u32();

	return v ?: 1;
}

static inline void sk_set_txhash(struct sock *sk)
{
	/* This pairs with READ_ONCE() in skb_set_hash_from_sk() */
	WRITE_ONCE(sk->sk_txhash, net_tx_rndhash());
}

static inline bool sk_rethink_txhash(struct sock *sk)
{
	if (sk->sk_txhash) {
		sk_set_txhash(sk);
		return true;
	}
	return false;
}

static inline struct dst_entry *
__sk_dst_get(struct sock *sk)
{
	return rcu_dereference_check(sk->sk_dst_cache,
				     lockdep_sock_is_held(sk));
}

static inline struct dst_entry *
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	rcu_read_lock();
	dst = rcu_dereference(sk->sk_dst_cache);
	if (dst && !atomic_inc_not_zero(&dst->__refcnt))
		dst = NULL;
	rcu_read_unlock();
	return dst;
}

static inline void __dst_negative_advice(struct sock *sk)
{
	struct dst_entry *ndst, *dst = __sk_dst_get(sk);

	if (dst && dst->ops->negative_advice) {
		ndst = dst->ops->negative_advice(dst);

		if (ndst != dst) {
			rcu_assign_pointer(sk->sk_dst_cache, ndst);
			sk_tx_queue_clear(sk);
			sk->sk_dst_pending_confirm = 0;
		}
	}
}

static inline void dst_negative_advice(struct sock *sk)
{
	sk_rethink_txhash(sk);
	__dst_negative_advice(sk);
}

struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie);

struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie);

static inline void sk_dst_confirm(struct sock *sk)
{
	if (!READ_ONCE(sk->sk_dst_pending_confirm))
		WRITE_ONCE(sk->sk_dst_pending_confirm, 1);
}

bool sk_mc_loop(struct sock *sk);

#define sk_can_gso(sk) net_gso_ok((sk)->sk_route_caps, (sk)->sk_gso_type)

void sk_setup_caps(struct sock *sk, struct dst_entry *dst);

static inline void sk_gso_disable(struct sock *sk)
{
	sk->sk_gso_disabled = 1;
	sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
}

static inline int skb_do_copy_data_nocache(struct sock *sk, struct sk_buff *skb,
					   struct iov_iter *from, char *to,
					   int copy, int offset)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		__wsum csum = 0;
		if (!csum_and_copy_from_iter_full(to, copy, &csum, from))
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, offset);
	} else if (sk->sk_route_caps & NETIF_F_NOCACHE_COPY) {
		if (!copy_from_iter_full_nocache(to, copy, from))
			return -EFAULT;
	} else if (!copy_from_iter_full(to, copy, from))
		return -EFAULT;

	return 0;
}

static inline int skb_add_data_nocache(struct sock *sk, struct sk_buff *skb,
				       struct iov_iter *from, int copy)
{
	int err, offset = skb->len;

	err = skb_do_copy_data_nocache(sk, skb, from, skb_put(skb, copy),
				       copy, offset);
	if (err)
		__skb_trim(skb, offset);

	return err;
}

int skb_copy_to_page_nocache(struct sock *sk, struct iov_iter *from,
			     struct sk_buff *skb,
			     struct page *page,
			     int off, int copy);

/**
 * sk_wmem_alloc_get - returns write allocations
 * @sk: socket
 *
 * Return: sk_wmem_alloc minus initial offset of one
 */
static inline int sk_wmem_alloc_get(const struct sock *sk)
{
	return refcount_read(&sk->sk_wmem_alloc) - 1;
}

/**
 * sk_rmem_alloc_get - returns read allocations
 * @sk: socket
 *
 * Return: sk_rmem_alloc
 */
static inline int sk_rmem_alloc_get(const struct sock *sk)
{
	return atomic_read(&sk->sk_rmem_alloc);
}

/**
 * sk_has_allocations - check if allocations are outstanding
 * @sk: socket
 *
 * Return: true if socket has write or read allocations
 */
static inline bool sk_has_allocations(const struct sock *sk)
{
	return sk_wmem_alloc_get(sk) || sk_rmem_alloc_get(sk);
}

/**
 * skwq_has_sleeper - check if there are any waiting processes
 * @wq: struct socket_wq
 *
 * Return: true if socket_wq has waiting processes
 *
 * The purpose of the skwq_has_sleeper and sock_poll_wait is to wrap the memory
 * barrier call. They were added due to the race found within the tcp code.
 *
 * Consider following tcp code paths::
 *
 *   CPU1                CPU2
 *   sys_select          receive packet
 *   ...                 ...
 *   __add_wait_queue    update tp->rcv_nxt
 *   ...                 ...
 *   tp->rcv_nxt check   sock_def_readable
 *   ...                 {
 *   schedule               rcu_read_lock();
 *                          wq = rcu_dereference(sk->sk_wq);
 *                          if (wq && waitqueue_active(&wq->wait))
 *                              wake_up_interruptible(&wq->wait)
 *                          ...
 *                       }
 *
 * The race for tcp fires when the __add_wait_queue changes done by CPU1 stay
 * in its cache, and so does the tp->rcv_nxt update on CPU2 side.  The CPU1
 * could then endup calling schedule and sleep forever if there are no more
 * data on the socket.
 *
 */
#define skwq_has_sleeper(wq) ({ (wq) && wq_has_sleeper(&(wq)->wait); })

/**
 * sock_poll_wait - place memory barrier behind the poll_wait call.
 * @filp:           file
 * @sock:           socket to wait on
 * @p:              poll_table
 *
 * See the comments in the wq_has_sleeper function.
 */
void sock_poll_wait(struct file *filp, struct socket *sock, struct poll_table_struct *p);

static inline void skb_set_hash_from_sk(struct sk_buff *skb, struct sock *sk)
{
	/* This pairs with WRITE_ONCE() in sk_set_txhash() */
	u32 txhash = READ_ONCE(sk->sk_txhash);

	if (txhash) {
		skb->l4_hash = 1;
		skb->hash = txhash;
	}
}

void skb_set_owner_w(struct sk_buff *skb, struct sock *sk);

/*
 *	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 *	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */
static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, skb->truesize);
}

static inline __must_check bool skb_set_owner_sk_safe(struct sk_buff *skb, struct sock *sk)
{
	if (sk && refcount_inc_not_zero(&sk->sk_refcnt)) {
		skb_orphan(skb);
		skb->destructor = sock_efree;
		skb->sk = sk;
		return true;
	}
	return false;
}

static inline void skb_prepare_for_gro(struct sk_buff *skb)
{
	if (skb->destructor != sock_wfree) {
		skb_orphan(skb);
		return;
	}
	skb->slow_gro = 1;
}

void sk_reset_timer(struct sock *sk, struct timer_list *timer,
		    unsigned long expires);

void sk_stop_timer(struct sock *sk, struct timer_list *timer);

void sk_stop_timer_sync(struct sock *sk, struct timer_list *timer);

int __sk_queue_drop_skb(struct sock *sk, struct sk_buff_head *sk_queue,
			struct sk_buff *skb, unsigned int flags,
			void (*destructor)(struct sock *sk,
					   struct sk_buff *skb));
int __sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);
int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);

int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb);
struct sk_buff *sock_dequeue_err_skb(struct sock *sk);

/*
 *	Recover an error report and clear atomically
 */

static inline int sock_error(struct sock *sk)
{
	int err;

	/* Avoid an atomic operation for the common case.
	 * This is racy since another cpu/thread can change sk_err under us.
	 */
	if (likely(data_race(!sk->sk_err)))
		return 0;

	err = xchg(&sk->sk_err, 0);
	return -err;
}

void sk_error_report(struct sock *sk);

static inline unsigned long sock_wspace(struct sock *sk)
{
	int amt = 0;

	if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
		amt = sk->sk_sndbuf - refcount_read(&sk->sk_wmem_alloc);
		if (amt < 0)
			amt = 0;
	}
	return amt;
}

/* Note:
 *  We use sk->sk_wq_raw, from contexts knowing this
 *  pointer is not NULL and cannot disappear/change.
 */
static inline void sk_set_bit(int nr, struct sock *sk)
{
	if ((nr == SOCKWQ_ASYNC_NOSPACE || nr == SOCKWQ_ASYNC_WAITDATA) &&
	    !sock_flag(sk, SOCK_FASYNC))
		return;

	set_bit(nr, &sk->sk_wq_raw->flags);
}

static inline void sk_clear_bit(int nr, struct sock *sk)
{
	if ((nr == SOCKWQ_ASYNC_NOSPACE || nr == SOCKWQ_ASYNC_WAITDATA) &&
	    !sock_flag(sk, SOCK_FASYNC))
		return;

	clear_bit(nr, &sk->sk_wq_raw->flags);
}

static inline void sk_wake_async(const struct sock *sk, int how, int band)
{
	if (sock_flag(sk, SOCK_FASYNC)) {
		rcu_read_lock();
		sock_wake_async(rcu_dereference(sk->sk_wq), how, band);
		rcu_read_unlock();
	}
}

/* Since sk_{r,w}mem_alloc sums skb->truesize, even a small frame might
 * need sizeof(sk_buff) + MTU + padding, unless net driver perform copybreak.
 * Note: for send buffers, TCP works better if we can build two skbs at
 * minimum.
 */
#define TCP_SKB_MIN_TRUESIZE	(2048 + SKB_DATA_ALIGN(sizeof(struct sk_buff)))

#define SOCK_MIN_SNDBUF		(TCP_SKB_MIN_TRUESIZE * 2)
#define SOCK_MIN_RCVBUF		 TCP_SKB_MIN_TRUESIZE

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	u32 val;

	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK)
		return;

	val = min(sk->sk_sndbuf, sk->sk_wmem_queued >> 1);
	val = max_t(u32, val, sk_unused_reserved_mem(sk));

	WRITE_ONCE(sk->sk_sndbuf, max_t(u32, val, SOCK_MIN_SNDBUF));
}

DECLARE_PER_TASK(struct page_frag, task_frag);

/**
 * sk_page_frag - return an appropriate page_frag
 * @sk: socket
 *
 * Use the per task page_frag instead of the per socket one for
 * optimization when we know that we're in process context and own
 * everything that's associated with %current.
 *
 * Both direct reclaim and page faults can nest inside other
 * socket operations and end up recursing into sk_page_frag()
 * while it's already in use: explicitly avoid task page_frag
 * usage if the caller is potentially doing any of them.
 * This assumes that page fault handlers use the GFP_NOFS flags.
 *
 * Return: a per task page_frag if context allows that,
 * otherwise a per socket one.
 */
extern struct page_frag *sk_page_frag(struct sock *sk);

bool sk_page_frag_refill(struct sock *sk, struct page_frag *pfrag);

/*
 *	Default write policy as shown to user space via poll/select/SIGIO
 */
static inline bool sock_writeable(const struct sock *sk)
{
	return refcount_read(&sk->sk_wmem_alloc) < (READ_ONCE(sk->sk_sndbuf) >> 1);
}

static inline gfp_t gfp_any(void)
{
	return in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
}

static inline gfp_t gfp_memcg_charge(void)
{
	return in_softirq() ? GFP_NOWAIT : GFP_KERNEL;
}

static inline long sock_rcvtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, bool noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	int v = waitall ? len : min_t(int, READ_ONCE(sk->sk_rcvlowat), len);

	return v ?: 1;
}

/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

struct sock_skb_cb {
	u32 dropcount;
};

/* Store sock_skb_cb at the end of skb->cb[] so protocol families
 * using skb->cb[] would keep using it directly and utilize its
 * alignement guarantee.
 */
#define SOCK_SKB_CB_OFFSET ((sizeof_field(struct sk_buff, cb) - \
			    sizeof(struct sock_skb_cb)))

#define SOCK_SKB_CB(__skb) ((struct sock_skb_cb *)((__skb)->cb + \
			    SOCK_SKB_CB_OFFSET))

#define sock_skb_cb_check_size(size) \
	BUILD_BUG_ON((size) > SOCK_SKB_CB_OFFSET)

static inline void
sock_skb_set_dropcount(const struct sock *sk, struct sk_buff *skb)
{
	SOCK_SKB_CB(skb)->dropcount = sock_flag(sk, SOCK_RXQ_OVFL) ?
						atomic_read(&sk->sk_drops) : 0;
}

static inline void sk_drops_add(struct sock *sk, const struct sk_buff *skb)
{
	int segs = max_t(u16, 1, skb_shinfo(skb)->gso_segs);

	atomic_add(segs, &sk->sk_drops);
}

static inline ktime_t sock_read_timestamp(struct sock *sk)
{
#if BITS_PER_LONG==32
	unsigned int seq;
	ktime_t kt;

	do {
		seq = read_seqbegin(&sk->sk_stamp_seq);
		kt = sk->sk_stamp;
	} while (read_seqretry(&sk->sk_stamp_seq, seq));

	return kt;
#else
	return READ_ONCE(sk->sk_stamp);
#endif
}

static inline void sock_write_timestamp(struct sock *sk, ktime_t kt)
{
#if BITS_PER_LONG==32
	write_seqlock(&sk->sk_stamp_seq);
	sk->sk_stamp = kt;
	write_sequnlock(&sk->sk_stamp_seq);
#else
	WRITE_ONCE(sk->sk_stamp, kt);
#endif
}

void __sock_recv_timestamp(struct msghdr *msg, struct sock *sk,
			   struct sk_buff *skb);
void __sock_recv_wifi_status(struct msghdr *msg, struct sock *sk,
			     struct sk_buff *skb);

static inline void
sock_recv_timestamp(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
	ktime_t kt = skb->tstamp;
	struct skb_shared_hwtstamps *hwtstamps = skb_hwtstamps(skb);

	/*
	 * generate control messages if
	 * - receive time stamping in software requested
	 * - software time stamp available and wanted
	 * - hardware time stamps available and wanted
	 */
	if (sock_flag(sk, SOCK_RCVTSTAMP) ||
	    (sk->sk_tsflags & SOF_TIMESTAMPING_RX_SOFTWARE) ||
	    (kt && sk->sk_tsflags & SOF_TIMESTAMPING_SOFTWARE) ||
	    (hwtstamps->hwtstamp &&
	     (sk->sk_tsflags & SOF_TIMESTAMPING_RAW_HARDWARE)))
		__sock_recv_timestamp(msg, sk, skb);
	else
		sock_write_timestamp(sk, kt);

	if (sock_flag(sk, SOCK_WIFI_STATUS) && skb->wifi_acked_valid)
		__sock_recv_wifi_status(msg, sk, skb);
}

void __sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
			      struct sk_buff *skb);

#define SK_DEFAULT_STAMP (-1L * NSEC_PER_SEC)
static inline void sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
					  struct sk_buff *skb)
{
#define FLAGS_TS_OR_DROPS ((1UL << SOCK_RXQ_OVFL)			| \
			   (1UL << SOCK_RCVTSTAMP))
#define TSFLAGS_ANY	  (SOF_TIMESTAMPING_SOFTWARE			| \
			   SOF_TIMESTAMPING_RAW_HARDWARE)

	if (sk->sk_flags & FLAGS_TS_OR_DROPS || sk->sk_tsflags & TSFLAGS_ANY)
		__sock_recv_ts_and_drops(msg, sk, skb);
	else if (unlikely(sock_flag(sk, SOCK_TIMESTAMP)))
		sock_write_timestamp(sk, skb->tstamp);
	else if (unlikely(sk->sk_stamp == SK_DEFAULT_STAMP))
		sock_write_timestamp(sk, 0);
}

void __sock_tx_timestamp(__u16 tsflags, __u8 *tx_flags);

/**
 * _sock_tx_timestamp - checks whether the outgoing packet is to be time stamped
 * @sk:		socket sending this packet
 * @tsflags:	timestamping flags to use
 * @tx_flags:	completed with instructions for time stamping
 * @tskey:      filled in with next sk_tskey (not for TCP, which uses seqno)
 *
 * Note: callers should take care of initial ``*tx_flags`` value (usually 0)
 */
static inline void _sock_tx_timestamp(struct sock *sk, __u16 tsflags,
				      __u8 *tx_flags, __u32 *tskey)
{
	if (unlikely(tsflags)) {
		__sock_tx_timestamp(tsflags, tx_flags);
		if (tsflags & SOF_TIMESTAMPING_OPT_ID && tskey &&
		    tsflags & SOF_TIMESTAMPING_TX_RECORD_MASK)
			*tskey = atomic_inc_return(&sk->sk_tskey) - 1;
	}
	if (unlikely(sock_flag(sk, SOCK_WIFI_STATUS)))
		*tx_flags |= SKBTX_WIFI_STATUS;
}

static inline void sock_tx_timestamp(struct sock *sk, __u16 tsflags,
				     __u8 *tx_flags)
{
	_sock_tx_timestamp(sk, tsflags, tx_flags, NULL);
}

static inline void skb_setup_tx_timestamp(struct sk_buff *skb, __u16 tsflags)
{
	_sock_tx_timestamp(skb->sk, tsflags, &skb_shinfo(skb)->tx_flags,
			   &skb_shinfo(skb)->tskey);
}

static inline bool sk_is_tcp(const struct sock *sk)
{
	return sk->sk_type == SOCK_STREAM && sk->sk_protocol == IPPROTO_TCP;
}

/**
 * sk_eat_skb - Release a skb if it is no longer needed
 * @sk: socket to eat this skb from
 * @skb: socket buffer to eat
 *
 * This routine must be called with interrupts disabled or with the socket
 * locked so that the sk_buff queue operation is ok.
*/
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}

static inline
void sock_net_set(struct sock *sk, struct net *net)
{
	write_pnet(&sk->sk_net, net);
}

static inline bool
skb_sk_is_prefetched(struct sk_buff *skb)
{
#ifdef CONFIG_INET
	return skb->destructor == sock_pfree;
#else
	return false;
#endif /* CONFIG_INET */
}

static inline bool
sk_is_refcounted(struct sock *sk)
{
	/* Only full sockets have sk->sk_flags. */
	return !sk_fullsock(sk) || !sock_flag(sk, SOCK_RCU_FREE);
}

/**
 * skb_steal_sock - steal a socket from an sk_buff
 * @skb: sk_buff to steal the socket from
 * @refcounted: is set to true if the socket is reference-counted
 */
static inline struct sock *
skb_steal_sock(struct sk_buff *skb, bool *refcounted)
{
	if (skb->sk) {
		struct sock *sk = skb->sk;

		*refcounted = true;
		if (skb_sk_is_prefetched(skb))
			*refcounted = sk_is_refcounted(sk);
		skb->destructor = NULL;
		skb->sk = NULL;
		return sk;
	}
	*refcounted = false;
	return NULL;
}

/* Checks if this SKB belongs to an HW offloaded socket
 * and whether any SW fallbacks are required based on dev.
 * Check decrypted mark in case skb_orphan() cleared socket.
 */
static inline struct sk_buff *sk_validate_xmit_skb(struct sk_buff *skb,
						   struct net_device *dev)
{
#ifdef CONFIG_SOCK_VALIDATE_XMIT
	struct sock *sk = skb->sk;

	if (sk && sk_fullsock(sk) && sk->sk_validate_xmit_skb) {
		skb = sk->sk_validate_xmit_skb(sk, dev, skb);
#ifdef CONFIG_TLS_DEVICE
	} else if (unlikely(skb->decrypted)) {
		pr_warn_ratelimited("unencrypted skb with no associated socket - dropping\n");
		kfree_skb(skb);
		skb = NULL;
#endif
	}
#endif

	return skb;
}

/* This helper checks if a socket is a LISTEN or NEW_SYN_RECV
 * SYNACK messages can be attached to either ones (depending on SYNCOOKIE)
 */
static inline bool sk_listener(const struct sock *sk)
{
	return (1 << sk->sk_state) & (TCPF_LISTEN | TCPF_NEW_SYN_RECV);
}

void sock_enable_timestamp(struct sock *sk, enum sock_flags flag);
int sock_recv_errqueue(struct sock *sk, struct msghdr *msg, int len, int level,
		       int type);

bool sk_ns_capable(const struct sock *sk,
		   struct user_namespace *user_ns, int cap);
bool sk_capable(const struct sock *sk, int cap);
bool sk_net_capable(const struct sock *sk, int cap);

void sk_get_meminfo(const struct sock *sk, u32 *meminfo);

/* Take into consideration the size of the struct sk_buff overhead in the
 * determination of these values, since that is non-constant across
 * platforms.  This makes socket queueing behavior and performance
 * not depend upon such differences.
 */
#define _SK_MEM_PACKETS		256
#define _SK_MEM_OVERHEAD	SKB_TRUESIZE(256)
#define SK_WMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)
#define SK_RMEM_MAX		(_SK_MEM_OVERHEAD * _SK_MEM_PACKETS)

extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

extern int sysctl_tstamp_allow_data;
extern int sysctl_optmem_max;

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

#define SKB_FRAG_PAGE_ORDER	get_order(32768)
DECLARE_STATIC_KEY_FALSE(net_high_order_alloc_disable_key);

static inline int sk_get_wmem0(const struct sock *sk, const struct proto *proto)
{
	/* Does this proto have per netns sysctl_wmem ? */
	if (proto->sysctl_wmem_offset)
		return *(int *)((void *)sock_net(sk) + proto->sysctl_wmem_offset);

	return *proto->sysctl_wmem;
}

static inline int sk_get_rmem0(const struct sock *sk, const struct proto *proto)
{
	/* Does this proto have per netns sysctl_rmem ? */
	if (proto->sysctl_rmem_offset)
		return *(int *)((void *)sock_net(sk) + proto->sysctl_rmem_offset);

	return *proto->sysctl_rmem;
}

/* Default TCP Small queue budget is ~1 ms of data (1sec >> 10)
 * Some wifi drivers need to tweak it to get more chunks.
 * They can use this helper from their ndo_start_xmit()
 */
static inline void sk_pacing_shift_update(struct sock *sk, int val)
{
	if (!sk || !sk_fullsock(sk) || READ_ONCE(sk->sk_pacing_shift) == val)
		return;
	WRITE_ONCE(sk->sk_pacing_shift, val);
}

/* if a socket is bound to a device, check that the given device
 * index is either the same or that the socket is bound to an L3
 * master device and the given device index is also enslaved to
 * that L3 master
 */
extern bool sk_dev_equal_l3scope(struct sock *sk, int dif);

void sock_def_readable(struct sock *sk);

int sock_bindtoindex(struct sock *sk, int ifindex, bool lock_sk);
void sock_set_timestamp(struct sock *sk, int optname, bool valbool);
int sock_set_timestamping(struct sock *sk, int optname,
			  struct so_timestamping timestamping);

void sock_enable_timestamps(struct sock *sk);
void sock_no_linger(struct sock *sk);
void sock_set_keepalive(struct sock *sk);
void sock_set_priority(struct sock *sk, u32 priority);
void sock_set_rcvbuf(struct sock *sk, int val);
void sock_set_mark(struct sock *sk, u32 val);
void sock_set_reuseaddr(struct sock *sk);
void sock_set_reuseport(struct sock *sk);
void sock_set_sndtimeo(struct sock *sk, s64 secs);

int sock_bind_add(struct sock *sk, struct sockaddr *addr, int addr_len);

int sock_get_timeout(long timeo, void *optval, bool old_timeval);
int sock_copy_user_timeval(struct __kernel_sock_timeval *tv,
			   sockptr_t optval, int optlen, bool old_timeval);

static inline bool sk_is_readable(struct sock *sk)
{
	if (sk->sk_prot->sock_is_readable)
		return sk->sk_prot->sock_is_readable(sk);
	return false;
}

#endif	/* _SOCK_API_H */
