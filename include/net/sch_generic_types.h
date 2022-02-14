/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_SCHED_GENERIC_TYPES_H
#define __NET_SCHED_GENERIC_TYPES_H

#include <linux/seqlock_api.h>
#include <linux/netdevice_api.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/percpu.h>
#include <linux/dynamic_queue_limits.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <net/gen_stats.h>
#include <net/rtnetlink.h>
#include <net/flow_offload.h>

struct Qdisc_ops;
struct qdisc_walker;
struct tcf_walker;
struct module;
struct bpf_flow_keys;

struct qdisc_rate_table {
	struct tc_ratespec rate;
	u32		data[256];
	struct qdisc_rate_table *next;
	int		refcnt;
};

enum qdisc_state_t {
	__QDISC_STATE_SCHED,
	__QDISC_STATE_DEACTIVATED,
	__QDISC_STATE_MISSED,
	__QDISC_STATE_DRAINING,
};

enum qdisc_state2_t {
	/* Only for !TCQ_F_NOLOCK qdisc. Never access it directly.
	 * Use qdisc_run_begin/end() or qdisc_is_running() instead.
	 */
	__QDISC_STATE2_RUNNING,
};

#define QDISC_STATE_MISSED	BIT(__QDISC_STATE_MISSED)
#define QDISC_STATE_DRAINING	BIT(__QDISC_STATE_DRAINING)

#define QDISC_STATE_NON_EMPTY	(QDISC_STATE_MISSED | \
					QDISC_STATE_DRAINING)

struct qdisc_size_table {
	struct rcu_head		rcu;
	struct list_head	list;
	struct tc_sizespec	szopts;
	int			refcnt;
	u16			data[];
};

/* similar to sk_buff_head, but skb->prev pointer is undefined. */
struct qdisc_skb_head {
	struct sk_buff	*head;
	struct sk_buff	*tail;
	__u32		qlen;
	spinlock_t	lock;
};

struct Qdisc {
	int 			(*enqueue)(struct sk_buff *skb,
					   struct Qdisc *sch,
					   struct sk_buff **to_free);
	struct sk_buff *	(*dequeue)(struct Qdisc *sch);
	unsigned int		flags;
#define TCQ_F_BUILTIN		1
#define TCQ_F_INGRESS		2
#define TCQ_F_CAN_BYPASS	4
#define TCQ_F_MQROOT		8
#define TCQ_F_ONETXQUEUE	0x10 /* dequeue_skb() can assume all skbs are for
				      * q->dev_queue : It can test
				      * netif_xmit_frozen_or_stopped() before
				      * dequeueing next packet.
				      * Its true for MQ/MQPRIO slaves, or non
				      * multiqueue device.
				      */
#define TCQ_F_WARN_NONWC	(1 << 16)
#define TCQ_F_CPUSTATS		0x20 /* run using percpu statistics */
#define TCQ_F_NOPARENT		0x40 /* root of its hierarchy :
				      * qdisc_tree_decrease_qlen() should stop.
				      */
#define TCQ_F_INVISIBLE		0x80 /* invisible by default in dump */
#define TCQ_F_NOLOCK		0x100 /* qdisc does not require locking */
#define TCQ_F_OFFLOADED		0x200 /* qdisc is offloaded to HW */
	u32			limit;
	const struct Qdisc_ops	*ops;
	struct qdisc_size_table	__rcu *stab;
	struct hlist_node       hash;
	u32			handle;
	u32			parent;

	struct netdev_queue	*dev_queue;

	struct net_rate_estimator __rcu *rate_est;
	struct gnet_stats_basic_sync __percpu *cpu_bstats;
	struct gnet_stats_queue	__percpu *cpu_qstats;
	int			pad;
	refcount_t		refcnt;

	/*
	 * For performance sake on SMP, we put highly modified fields at the end
	 */
	struct sk_buff_head	gso_skb ____cacheline_aligned_in_smp;
	struct qdisc_skb_head	q;
	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue	qstats;
	unsigned long		state;
	unsigned long		state2; /* must be written under qdisc spinlock */
	struct Qdisc            *next_sched;
	struct sk_buff_head	skb_bad_txq;

	spinlock_t		busylock ____cacheline_aligned_in_smp;
	spinlock_t		seqlock;

	struct rcu_head		rcu;
	netdevice_tracker	dev_tracker;
	/* private data */
	long privdata[] ____cacheline_aligned;
};

struct Qdisc_class_ops {
	unsigned int		flags;
	/* Child qdisc manipulation */
	struct netdev_queue *	(*select_queue)(struct Qdisc *, struct tcmsg *);
	int			(*graft)(struct Qdisc *, unsigned long cl,
					struct Qdisc *, struct Qdisc **,
					struct netlink_ext_ack *extack);
	struct Qdisc *		(*leaf)(struct Qdisc *, unsigned long cl);
	void			(*qlen_notify)(struct Qdisc *, unsigned long);

	/* Class manipulation routines */
	unsigned long		(*find)(struct Qdisc *, u32 classid);
	int			(*change)(struct Qdisc *, u32, u32,
					struct nlattr **, unsigned long *,
					struct netlink_ext_ack *);
	int			(*delete)(struct Qdisc *, unsigned long,
					  struct netlink_ext_ack *);
	void			(*walk)(struct Qdisc *, struct qdisc_walker * arg);

	/* Filter manipulation */
	struct tcf_block *	(*tcf_block)(struct Qdisc *sch,
					     unsigned long arg,
					     struct netlink_ext_ack *extack);
	unsigned long		(*bind_tcf)(struct Qdisc *, unsigned long,
					u32 classid);
	void			(*unbind_tcf)(struct Qdisc *, unsigned long);

	/* rtnetlink specific */
	int			(*dump)(struct Qdisc *, unsigned long,
					struct sk_buff *skb, struct tcmsg*);
	int			(*dump_stats)(struct Qdisc *, unsigned long,
					struct gnet_dump *);
};

struct qdisc_skb_cb {
	struct {
		unsigned int		pkt_len;
		u16			slave_dev_queue_mapping;
		u16			tc_classid;
	};
#define QDISC_CB_PRIV_LEN 20
	unsigned char		data[QDISC_CB_PRIV_LEN];
};

#endif /* _NET_SCHED_GENERIC_TYPES_H */
