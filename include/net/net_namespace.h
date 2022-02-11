/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Operations on the network namespace
 */
#ifndef __NET_NET_NAMESPACE_H
#define __NET_NET_NAMESPACE_H

#include <net/net_namespace_types.h>

#ifndef CONFIG_NET_NS
#include <linux/sched.h>
#include <linux/nsproxy.h>
#endif

struct user_namespace;
struct proc_dir_entry;
struct net_device;
struct sock;
struct ctl_table_header;
struct net_generic;
struct uevent_sock;
struct netns_ipvs;
struct bpf_prog;

#ifdef CONFIG_NET_NS
struct net *copy_net_ns(unsigned long flags, struct user_namespace *user_ns,
			struct net *old_net);

void net_ns_get_ownership(const struct net *net, kuid_t *uid, kgid_t *gid);

void net_ns_barrier(void);

struct ns_common *get_net_ns(struct ns_common *ns);
struct net *get_net_ns_by_fd(int fd);
#else /* CONFIG_NET_NS */
static inline struct net *copy_net_ns(unsigned long flags,
	struct user_namespace *user_ns, struct net *old_net)
{
	if (flags & CLONE_NEWNET)
		return ERR_PTR(-EINVAL);
	return old_net;
}

static inline void net_ns_get_ownership(const struct net *net,
					kuid_t *uid, kgid_t *gid)
{
	*uid = GLOBAL_ROOT_UID;
	*gid = GLOBAL_ROOT_GID;
}

static inline void net_ns_barrier(void) {}

static inline struct ns_common *get_net_ns(struct ns_common *ns)
{
	return ERR_PTR(-EINVAL);
}

static inline struct net *get_net_ns_by_fd(int fd)
{
	return ERR_PTR(-EINVAL);
}
#endif /* CONFIG_NET_NS */


extern struct list_head net_namespace_list;

struct net *get_net_ns_by_pid(pid_t pid);

#ifdef CONFIG_SYSCTL
void ipx_register_sysctl(void);
void ipx_unregister_sysctl(void);
#else
#define ipx_register_sysctl()
#define ipx_unregister_sysctl()
#endif

#ifdef CONFIG_NET_NS
void __put_net(struct net *net);

/* Try using get_net_track() instead */
static inline struct net *get_net(struct net *net)
{
	refcount_inc(&net->ns.count);
	return net;
}

static inline struct net *maybe_get_net(struct net *net)
{
	/* Used when we know struct net exists but we
	 * aren't guaranteed a previous reference count
	 * exists.  If the reference count is zero this
	 * function fails and returns NULL.
	 */
	if (!refcount_inc_not_zero(&net->ns.count))
		net = NULL;
	return net;
}

/* Try using put_net_track() instead */
static inline void put_net(struct net *net)
{
	if (refcount_dec_and_test(&net->ns.count))
		__put_net(net);
}

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return net1 == net2;
}

static inline int check_net(const struct net *net)
{
	return refcount_read(&net->ns.count) != 0;
}

void net_drop_ns(void *);

#else

static inline struct net *get_net(struct net *net)
{
	return net;
}

static inline void put_net(struct net *net)
{
}

static inline struct net *maybe_get_net(struct net *net)
{
	return net;
}

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return 1;
}

static inline int check_net(const struct net *net)
{
	return 1;
}

#define net_drop_ns NULL
#endif


static inline void netns_tracker_alloc(struct net *net,
				       netns_tracker *tracker, gfp_t gfp)
{
#ifdef CONFIG_NET_NS_REFCNT_TRACKER
	ref_tracker_alloc(&net->refcnt_tracker, tracker, gfp);
#endif
}

static inline void netns_tracker_free(struct net *net,
				      netns_tracker *tracker)
{
#ifdef CONFIG_NET_NS_REFCNT_TRACKER
       ref_tracker_free(&net->refcnt_tracker, tracker);
#endif
}

static inline struct net *get_net_track(struct net *net,
					netns_tracker *tracker, gfp_t gfp)
{
	get_net(net);
	netns_tracker_alloc(net, tracker, gfp);
	return net;
}

static inline void put_net_track(struct net *net, netns_tracker *tracker)
{
	netns_tracker_free(net, tracker);
	put_net(net);
}

static inline void write_pnet(possible_net_t *pnet, struct net *net)
{
#ifdef CONFIG_NET_NS
	pnet->net = net;
#endif
}

static inline struct net *read_pnet(const possible_net_t *pnet)
{
#ifdef CONFIG_NET_NS
	return pnet->net;
#else
	return &init_net;
#endif
}

/* Protected by net_rwsem */
#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)
#define for_each_net_continue_reverse(VAR)		\
	list_for_each_entry_continue_reverse(VAR, &net_namespace_list, list)
#define for_each_net_rcu(VAR)				\
	list_for_each_entry_rcu(VAR, &net_namespace_list, list)

int peernet2id_alloc(struct net *net, struct net *peer, gfp_t gfp);
int peernet2id(const struct net *net, struct net *peer);
bool peernet_has_id(const struct net *net, struct net *peer);
struct net *get_net_ns_by_id(const struct net *net, int id);

/*
 * Use these carefully.  If you implement a network device and it
 * needs per network namespace operations use device pernet operations,
 * otherwise use pernet subsys operations.
 *
 * Network interfaces need to be removed from a dying netns _before_
 * subsys notifiers can be called, as most of the network code cleanup
 * (which is done from subsys notifiers) runs with the assumption that
 * dev_remove_pack has been called so no new packets will arrive during
 * and after the cleanup functions have been called.  dev_remove_pack
 * is not per namespace so instead the guarantee of no more packets
 * arriving in a network namespace is provided by ensuring that all
 * network devices and all sockets have left the network namespace
 * before the cleanup methods are called.
 *
 * For the longest time the ipv4 icmp code was registered as a pernet
 * device which caused kernel oops, and panics during network
 * namespace cleanup.   So please don't get this wrong.
 */
int register_pernet_subsys(struct pernet_operations *);
void unregister_pernet_subsys(struct pernet_operations *);
int register_pernet_device(struct pernet_operations *);
void unregister_pernet_device(struct pernet_operations *);

struct ctl_table;

#ifdef CONFIG_SYSCTL
int net_sysctl_init(void);
struct ctl_table_header *register_net_sysctl(struct net *net, const char *path,
					     struct ctl_table *table);
void unregister_net_sysctl_table(struct ctl_table_header *header);
#else
static inline int net_sysctl_init(void) { return 0; }
static inline struct ctl_table_header *register_net_sysctl(struct net *net,
	const char *path, struct ctl_table *table)
{
	return NULL;
}
static inline void unregister_net_sysctl_table(struct ctl_table_header *header)
{
}
#endif

static inline int rt_genid_ipv4(const struct net *net)
{
	return atomic_read(&net->ipv4.rt_genid);
}

#if IS_ENABLED(CONFIG_IPV6)
static inline int rt_genid_ipv6(const struct net *net)
{
	return atomic_read(&net->ipv6.fib6_sernum);
}
#endif

static inline void rt_genid_bump_ipv4(struct net *net)
{
	atomic_inc(&net->ipv4.rt_genid);
}

extern void (*__fib6_flush_trees)(struct net *net);
static inline void rt_genid_bump_ipv6(struct net *net)
{
	if (__fib6_flush_trees)
		__fib6_flush_trees(net);
}

#if IS_ENABLED(CONFIG_IEEE802154_6LOWPAN)
static inline struct netns_ieee802154_lowpan *
net_ieee802154_lowpan(struct net *net)
{
	return &net->ieee802154_lowpan;
}
#endif

/* For callers who don't really care about whether it's IPv4 or IPv6 */
static inline void rt_genid_bump_all(struct net *net)
{
	rt_genid_bump_ipv4(net);
	rt_genid_bump_ipv6(net);
}

static inline int fnhe_genid(const struct net *net)
{
	return atomic_read(&net->fnhe_genid);
}

static inline void fnhe_genid_bump(struct net *net)
{
	atomic_inc(&net->fnhe_genid);
}

#ifdef CONFIG_NET
void net_ns_init(void);
#else
static inline void net_ns_init(void) {}
#endif

#endif /* __NET_NET_NAMESPACE_H */
