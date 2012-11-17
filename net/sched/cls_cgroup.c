/*
 * net/sched/cls_cgroup.c	Control Group Classifier
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/cgroup.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <net/rtnetlink.h>
#include <net/pkt_cls.h>
#include <net/sock.h>
#include <net/cls_cgroup.h>

static DEFINE_MUTEX(netcls_mutex);

static inline struct cgroup_cls_state *cgrp_cls_state(struct cgroup *cgrp)
{
	return container_of(cgroup_subsys_state(cgrp, net_cls_subsys_id),
			    struct cgroup_cls_state, css);
}

static inline struct cgroup_cls_state *task_cls_state(struct task_struct *p)
{
	return container_of(task_subsys_state(p, net_cls_subsys_id),
			    struct cgroup_cls_state, css);
}

static struct cgroup_subsys_state *cgrp_css_alloc(struct cgroup *cgrp)
{
	struct cgroup_cls_state *cs;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return ERR_PTR(-ENOMEM);

	return &cs->css;
}

/* @cgrp coming online, inherit the parent's classid */
static int cgrp_css_online(struct cgroup *cgrp)
{
	if (!cgrp->parent)
		return 0;

	mutex_lock(&netcls_mutex);
	cgrp_cls_state(cgrp)->classid = cgrp_cls_state(cgrp->parent)->classid;
	mutex_unlock(&netcls_mutex);
	return 0;
}

static void cgrp_css_free(struct cgroup *cgrp)
{
	kfree(cgrp_cls_state(cgrp));
}

static u64 read_classid(struct cgroup *cgrp, struct cftype *cft)
{
	return cgrp_cls_state(cgrp)->classid;
}

/**
 * propagate_classid - proapgate classid configuration downwards
 * @root: cgroup to propagate classid down from
 *
 * Propagate @root's classid to descendants of @root.  Each descendant of
 * @root re-inherits from its parent in pre-order tree walk.  This should
 * be called after the classid of @root is changed to keep the descendants
 * up-to-date.
 *
 * This may race with a new cgroup coming online and propagation may happen
 * before finishing ->css_online() or while being taken offline.  As a
 * cgroup_cls_state is ready after ->css_alloc() and propagation doesn't
 * affect the parent, this is safe.
 *
 * Should be called with netcls_mutex held.
 */
static void propagate_classid(struct cgroup *root)
{
	struct cgroup *pos;

	lockdep_assert_held(&netcls_mutex);
	rcu_read_lock();

	cgroup_for_each_descendant_pre(pos, root) {
		struct cgroup_cls_state *cs = cgrp_cls_state(pos);

		/*
		 * Don't propagate if @pos has local configuration.  We can
		 * skip @pos's subtree but don't have to.  Just propagate
		 * through for simplicity.
		 */
		if (!cs->is_local)
			cs->classid = cgrp_cls_state(pos->parent)->classid;
	}

	rcu_read_unlock();
}

static int write_classid(struct cgroup *cgrp, struct cftype *cft,
			 const char *buf)
{
	struct cgroup_cls_state *cs = cgrp_cls_state(cgrp);
	s64 v;

	if (sscanf(buf, "%lld", &v) != 1)
		return -EINVAL;

	mutex_lock(&netcls_mutex);

	if (v >= 0) {
		cs->classid = clamp_val(v, 0, UINT_MAX);
		cs->is_local = true;
	} else {
		if (cgrp->parent)
			cs->classid = cgrp_cls_state(cgrp->parent)->classid;
		else
			cs->classid = 0;
		cs->is_local = false;
	}
	propagate_classid(cgrp);

	mutex_unlock(&netcls_mutex);
	return 0;
}

static u64 read_is_local(struct cgroup *cgrp, struct cftype *cft)
{
	return cgrp_cls_state(cgrp)->is_local;
}

static struct cftype ss_files[] = {
	{
		.name = "classid",
		.read_u64 = read_classid,
		.write_string = write_classid,
	},
	{
		.name = "is_local",
		.read_u64 = read_is_local,
	},
	{ }	/* terminate */
};

struct cgroup_subsys net_cls_subsys = {
	.name		= "net_cls",
	.css_alloc	= cgrp_css_alloc,
	.css_online	= cgrp_css_online,
	.css_free	= cgrp_css_free,
	.subsys_id	= net_cls_subsys_id,
	.base_cftypes	= ss_files,
	.module		= THIS_MODULE,
};

struct cls_cgroup_head {
	u32			handle;
	struct tcf_exts		exts;
	struct tcf_ematch_tree	ematches;
};

static int cls_cgroup_classify(struct sk_buff *skb, const struct tcf_proto *tp,
			       struct tcf_result *res)
{
	struct cls_cgroup_head *head = tp->root;
	u32 classid;

	rcu_read_lock();
	classid = task_cls_state(current)->classid;
	rcu_read_unlock();

	/*
	 * Due to the nature of the classifier it is required to ignore all
	 * packets originating from softirq context as accessing `current'
	 * would lead to false results.
	 *
	 * This test assumes that all callers of dev_queue_xmit() explicitely
	 * disable bh. Knowing this, it is possible to detect softirq based
	 * calls by looking at the number of nested bh disable calls because
	 * softirqs always disables bh.
	 */
	if (in_serving_softirq()) {
		/* If there is an sk_classid we'll use that. */
		if (!skb->sk)
			return -1;
		classid = skb->sk->sk_classid;
	}

	if (!classid)
		return -1;

	if (!tcf_em_tree_match(skb, &head->ematches, NULL))
		return -1;

	res->classid = classid;
	res->class = 0;
	return tcf_exts_exec(skb, &head->exts, res);
}

static unsigned long cls_cgroup_get(struct tcf_proto *tp, u32 handle)
{
	return 0UL;
}

static void cls_cgroup_put(struct tcf_proto *tp, unsigned long f)
{
}

static int cls_cgroup_init(struct tcf_proto *tp)
{
	return 0;
}

static const struct tcf_ext_map cgroup_ext_map = {
	.action = TCA_CGROUP_ACT,
	.police = TCA_CGROUP_POLICE,
};

static const struct nla_policy cgroup_policy[TCA_CGROUP_MAX + 1] = {
	[TCA_CGROUP_EMATCHES]	= { .type = NLA_NESTED },
};

static int cls_cgroup_change(struct sk_buff *in_skb,
			     struct tcf_proto *tp, unsigned long base,
			     u32 handle, struct nlattr **tca,
			     unsigned long *arg)
{
	struct nlattr *tb[TCA_CGROUP_MAX + 1];
	struct cls_cgroup_head *head = tp->root;
	struct tcf_ematch_tree t;
	struct tcf_exts e;
	int err;

	if (!tca[TCA_OPTIONS])
		return -EINVAL;

	if (head == NULL) {
		if (!handle)
			return -EINVAL;

		head = kzalloc(sizeof(*head), GFP_KERNEL);
		if (head == NULL)
			return -ENOBUFS;

		head->handle = handle;

		tcf_tree_lock(tp);
		tp->root = head;
		tcf_tree_unlock(tp);
	}

	if (handle != head->handle)
		return -ENOENT;

	err = nla_parse_nested(tb, TCA_CGROUP_MAX, tca[TCA_OPTIONS],
			       cgroup_policy);
	if (err < 0)
		return err;

	err = tcf_exts_validate(tp, tb, tca[TCA_RATE], &e, &cgroup_ext_map);
	if (err < 0)
		return err;

	err = tcf_em_tree_validate(tp, tb[TCA_CGROUP_EMATCHES], &t);
	if (err < 0)
		return err;

	tcf_exts_change(tp, &head->exts, &e);
	tcf_em_tree_change(tp, &head->ematches, &t);

	return 0;
}

static void cls_cgroup_destroy(struct tcf_proto *tp)
{
	struct cls_cgroup_head *head = tp->root;

	if (head) {
		tcf_exts_destroy(tp, &head->exts);
		tcf_em_tree_destroy(tp, &head->ematches);
		kfree(head);
	}
}

static int cls_cgroup_delete(struct tcf_proto *tp, unsigned long arg)
{
	return -EOPNOTSUPP;
}

static void cls_cgroup_walk(struct tcf_proto *tp, struct tcf_walker *arg)
{
	struct cls_cgroup_head *head = tp->root;

	if (arg->count < arg->skip)
		goto skip;

	if (arg->fn(tp, (unsigned long) head, arg) < 0) {
		arg->stop = 1;
		return;
	}
skip:
	arg->count++;
}

static int cls_cgroup_dump(struct tcf_proto *tp, unsigned long fh,
			   struct sk_buff *skb, struct tcmsg *t)
{
	struct cls_cgroup_head *head = tp->root;
	unsigned char *b = skb_tail_pointer(skb);
	struct nlattr *nest;

	t->tcm_handle = head->handle;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	if (tcf_exts_dump(skb, &head->exts, &cgroup_ext_map) < 0 ||
	    tcf_em_tree_dump(skb, &head->ematches, TCA_CGROUP_EMATCHES) < 0)
		goto nla_put_failure;

	nla_nest_end(skb, nest);

	if (tcf_exts_dump_stats(skb, &head->exts, &cgroup_ext_map) < 0)
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static struct tcf_proto_ops cls_cgroup_ops __read_mostly = {
	.kind		=	"cgroup",
	.init		=	cls_cgroup_init,
	.change		=	cls_cgroup_change,
	.classify	=	cls_cgroup_classify,
	.destroy	=	cls_cgroup_destroy,
	.get		=	cls_cgroup_get,
	.put		=	cls_cgroup_put,
	.delete		=	cls_cgroup_delete,
	.walk		=	cls_cgroup_walk,
	.dump		=	cls_cgroup_dump,
	.owner		=	THIS_MODULE,
};

static int __init init_cgroup_cls(void)
{
	int ret;

	ret = cgroup_load_subsys(&net_cls_subsys);
	if (ret)
		goto out;

	ret = register_tcf_proto_ops(&cls_cgroup_ops);
	if (ret)
		cgroup_unload_subsys(&net_cls_subsys);

out:
	return ret;
}

static void __exit exit_cgroup_cls(void)
{
	unregister_tcf_proto_ops(&cls_cgroup_ops);

	cgroup_unload_subsys(&net_cls_subsys);
}

module_init(init_cgroup_cls);
module_exit(exit_cgroup_cls);
MODULE_LICENSE("GPL");
