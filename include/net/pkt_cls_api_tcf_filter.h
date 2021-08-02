/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_PKT_CLS_API_TCF_FILTER_H
#define __NET_PKT_CLS_API_TCF_FILTER_H

#include <net/pkt_cls.h>

#include <net/sch_generic_api.h>

static inline unsigned long
__cls_set_class(unsigned long *clp, unsigned long cl)
{
	return xchg(clp, cl);
}

static inline void
__tcf_bind_filter(struct Qdisc *q, struct tcf_result *r, unsigned long base)
{
	unsigned long cl;

	cl = q->ops->cl_ops->bind_tcf(q, base, r->classid);
	cl = __cls_set_class(&r->class, cl);
	if (cl)
		q->ops->cl_ops->unbind_tcf(q, cl);
}

static inline void
tcf_bind_filter(struct tcf_proto *tp, struct tcf_result *r, unsigned long base)
{
	struct Qdisc *q = tp->chain->block->q;

	/* Check q as it is not set for shared blocks. In that case,
	 * setting class is not supported.
	 */
	if (!q)
		return;
	sch_tree_lock(q);
	__tcf_bind_filter(q, r, base);
	sch_tree_unlock(q);
}

static inline void
__tcf_unbind_filter(struct Qdisc *q, struct tcf_result *r)
{
	unsigned long cl;

	if ((cl = __cls_set_class(&r->class, 0)) != 0)
		q->ops->cl_ops->unbind_tcf(q, cl);
}

static inline void
tcf_unbind_filter(struct tcf_proto *tp, struct tcf_result *r)
{
	struct Qdisc *q = tp->chain->block->q;

	if (!q)
		return;
	__tcf_unbind_filter(q, r);
}

#endif /* __NET_PKT_CLS_API_TCF_FILTER_H */
