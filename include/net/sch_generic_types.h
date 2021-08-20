/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_SCHED_GENERIC_TYPES_H
#define __NET_SCHED_GENERIC_TYPES_H

#include <linux/rwsem_types.h>

#include <net/gen_stats.h>
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

struct tcf_result {
	union {
		struct {
			unsigned long	class;
			u32		classid;
		};
		const struct tcf_proto *goto_tp;

		/* used in the skb_tc_reinsert function */
		struct {
			bool		ingress;
			struct gnet_stats_queue *qstats;
		};
	};
};

struct tcf_chain;

struct tcf_proto_ops {
	struct list_head	head;
	char			kind[IFNAMSIZ];

	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto *,
					    struct tcf_result *);
	int			(*init)(struct tcf_proto*);
	void			(*destroy)(struct tcf_proto *tp, bool rtnl_held,
					   struct netlink_ext_ack *extack);

	void*			(*get)(struct tcf_proto*, u32 handle);
	void			(*put)(struct tcf_proto *tp, void *f);
	int			(*change)(struct net *net, struct sk_buff *,
					struct tcf_proto*, unsigned long,
					u32 handle, struct nlattr **,
					void **, u32,
					struct netlink_ext_ack *);
	int			(*delete)(struct tcf_proto *tp, void *arg,
					  bool *last, bool rtnl_held,
					  struct netlink_ext_ack *);
	bool			(*delete_empty)(struct tcf_proto *tp);
	void			(*walk)(struct tcf_proto *tp,
					struct tcf_walker *arg, bool rtnl_held);
	int			(*reoffload)(struct tcf_proto *tp, bool add,
					     flow_setup_cb_t *cb, void *cb_priv,
					     struct netlink_ext_ack *extack);
	void			(*hw_add)(struct tcf_proto *tp,
					  void *type_data);
	void			(*hw_del)(struct tcf_proto *tp,
					  void *type_data);
	void			(*bind_class)(void *, u32, unsigned long,
					      void *, unsigned long);
	void *			(*tmplt_create)(struct net *net,
						struct tcf_chain *chain,
						struct nlattr **tca,
						struct netlink_ext_ack *extack);
	void			(*tmplt_destroy)(void *tmplt_priv);

	/* rtnetlink specific */
	int			(*dump)(struct net*, struct tcf_proto*, void *,
					struct sk_buff *skb, struct tcmsg*,
					bool);
	int			(*terse_dump)(struct net *net,
					      struct tcf_proto *tp, void *fh,
					      struct sk_buff *skb,
					      struct tcmsg *t, bool rtnl_held);
	int			(*tmplt_dump)(struct sk_buff *skb,
					      struct net *net,
					      void *tmplt_priv);

	struct module		*owner;
	int			flags;
};

/* Classifiers setting TCF_PROTO_OPS_DOIT_UNLOCKED in tcf_proto_ops->flags
 * are expected to implement tcf_proto_ops->delete_empty(), otherwise race
 * conditions can occur when filters are inserted/deleted simultaneously.
 */
enum tcf_proto_ops_flags {
	TCF_PROTO_OPS_DOIT_UNLOCKED = 1,
};

struct tcf_proto {
	/* Fast access part */
	struct tcf_proto __rcu	*next;
	void __rcu		*root;

	/* called under RCU BH lock*/
	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto *,
					    struct tcf_result *);
	__be16			protocol;

	/* All the rest */
	u32			prio;
	void			*data;
	const struct tcf_proto_ops	*ops;
	struct tcf_chain	*chain;
	/* Lock protects tcf_proto shared state and can be used by unlocked
	 * classifiers to protect their private data.
	 */
	spinlock_t		lock;
	bool			deleting;
	refcount_t		refcnt;
	struct rcu_head		rcu;
	struct hlist_node	destroy_ht_node;
};

typedef void tcf_chain_head_change_t(struct tcf_proto *tp_head, void *priv);

struct tcf_chain {
	/* Protects filter_chain. */
	struct mutex filter_chain_lock;
	struct tcf_proto __rcu *filter_chain;
	struct list_head list;
	struct tcf_block *block;
	u32 index; /* chain index */
	unsigned int refcnt;
	unsigned int action_refcnt;
	bool explicitly_created;
	bool flushing;
	const struct tcf_proto_ops *tmplt_ops;
	void *tmplt_priv;
	struct rcu_head rcu;
};

struct tcf_block {
	/* Lock protects tcf_block and lifetime-management data of chains
	 * attached to the block (refcnt, action_refcnt, explicitly_created).
	 */
	struct mutex lock;
	struct list_head chain_list;
	u32 index; /* block index for shared blocks */
	u32 classid; /* which class this block belongs to */
	refcount_t refcnt;
	struct net *net;
	struct Qdisc *q;
	struct rw_semaphore cb_lock; /* protects cb_list and offload counters */
	struct flow_block flow_block;
	struct list_head owner_list;
	bool keep_dst;
	atomic_t offloadcnt; /* Number of oddloaded filters */
	unsigned int nooffloaddevcnt; /* Number of devs unable to do offload */
	unsigned int lockeddevcnt; /* Number of devs that require rtnl lock. */
	struct {
		struct tcf_chain *chain;
		struct list_head filter_chain_list;
	} chain0;
	struct rcu_head rcu;
	DECLARE_HASHTABLE(proto_destroy_ht, 7);
	struct mutex proto_destroy_lock; /* Lock for proto_destroy hashtable. */
};

struct psched_ratecfg {
	u64	rate_bytes_ps; /* bytes per second */
	u32	mult;
	u16	overhead;
	u16	mpu;
	u8	linklayer;
	u8	shift;
};

#define QDISC_CB_PRIV_LEN 20

struct qdisc_skb_cb {
	struct {
		unsigned int		pkt_len;
		u16			slave_dev_queue_mapping;
		u16			tc_classid;
	};

	unsigned char		data[QDISC_CB_PRIV_LEN];
};

static inline struct qdisc_skb_cb *qdisc_skb_cb(const struct sk_buff *skb)
{
	return (struct qdisc_skb_cb *)skb->cb;
}

#endif /* _NET_SCHED_GENERIC_TYPES_H */
