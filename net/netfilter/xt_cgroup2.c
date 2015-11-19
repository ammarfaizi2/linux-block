#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/cgroup.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_cgroup2.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tejun Heo <tj@kernel.org>");
MODULE_DESCRIPTION("Xtables: cgroup2 socket ownership matching");
MODULE_ALIAS("ipt_cgroup2");
MODULE_ALIAS("ip6t_cgroup2");

static int cgroup2_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_cgroup2_info *info = par->matchinfo;
	struct cgroup *cgrp;

	if (info->invert & ~1)
		return -EINVAL;

	cgrp = cgroup_get_from_path(info->path);
	if (IS_ERR(cgrp)) {
		pr_info("xt_cgroup2: invalid path, errno=%ld\n", PTR_ERR(cgrp));
		return -EINVAL;
	}
	info->priv = cgrp;

	return 0;
}

static bool cgroup2_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_cgroup2_info *info = par->matchinfo;
	struct cgroup *ancestor = info->priv;
	struct cgroup *cgrp;

	if (!skb->sk || !sk_fullsock(skb->sk))
		return false;

	cgrp = sock_cgroup_ptr(&skb->sk->sk_cgrp_data);

	return cgroup_is_descendant(cgrp, ancestor) ^ info->invert;
}

static void cgroup2_mt_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_cgroup2_info *info = par->matchinfo;

	cgroup_put(info->priv);
}

static struct xt_match cgroup2_mt_reg __read_mostly = {
	.name		= "cgroup2",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.checkentry	= cgroup2_mt_check,
	.match		= cgroup2_mt,
	.matchsize	= sizeof(struct xt_cgroup2_info),
	.destroy	= cgroup2_mt_destroy,
	.me		= THIS_MODULE,
	.hooks		= (1 << NF_INET_LOCAL_OUT) |
			  (1 << NF_INET_POST_ROUTING) |
			  (1 << NF_INET_LOCAL_IN),
};

static int __init cgroup2_mt_init(void)
{
	return xt_register_match(&cgroup2_mt_reg);
}

static void __exit cgroup2_mt_exit(void)
{
	xt_unregister_match(&cgroup2_mt_reg);
}

module_init(cgroup2_mt_init);
module_exit(cgroup2_mt_exit);
