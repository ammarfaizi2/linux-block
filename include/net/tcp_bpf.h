/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP module.
 *
 * Version:	@(#)tcp.h	1.0.5	05/23/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 */
#ifndef _TCP_BPF_H
#define _TCP_BPF_H

#include <linux/filter_api.h>
#include <net/tcp.h>
#include <linux/bpf-cgroup-api.h>

#ifdef CONFIG_NET_SOCK_MSG
struct sk_msg;
struct sk_psock;

#ifdef CONFIG_BPF_SYSCALL
struct proto *tcp_bpf_get_proto(struct sock *sk, struct sk_psock *psock);
int tcp_bpf_update_proto(struct sock *sk, struct sk_psock *psock, bool restore);
void tcp_bpf_clone(const struct sock *sk, struct sock *newsk);
#endif /* CONFIG_BPF_SYSCALL */

int tcp_bpf_sendmsg_redir(struct sock *sk, struct sk_msg *msg, u32 bytes,
			  int flags);
#endif /* CONFIG_NET_SOCK_MSG */

#if !defined(CONFIG_BPF_SYSCALL) || !defined(CONFIG_NET_SOCK_MSG)
static inline void tcp_bpf_clone(const struct sock *sk, struct sock *newsk)
{
}
#endif

#ifdef CONFIG_CGROUP_BPF
static inline void bpf_skops_init_skb(struct bpf_sock_ops_kern *skops,
				      struct sk_buff *skb,
				      unsigned int end_offset)
{
	skops->skb = skb;
	skops->skb_data_end = skb->data + end_offset;
}
#else
static inline void bpf_skops_init_skb(struct bpf_sock_ops_kern *skops,
				      struct sk_buff *skb,
				      unsigned int end_offset)
{
}
#endif

/* Call BPF_SOCK_OPS program that returns an int. If the return value
 * is < 0, then the BPF op failed (for example if the loaded BPF
 * program does not support the chosen operation or there is no BPF
 * program loaded).
 */
#ifdef CONFIG_BPF
static inline int tcp_call_bpf(struct sock *sk, int op, u32 nargs, u32 *args)
{
	struct bpf_sock_ops_kern sock_ops;
	int ret;

	memset(&sock_ops, 0, offsetof(struct bpf_sock_ops_kern, temp));
	if (sk_fullsock(sk)) {
		sock_ops.is_fullsock = 1;
		sock_owned_by_me(sk);
	}

	sock_ops.sk = sk;
	sock_ops.op = op;
	if (nargs > 0)
		memcpy(sock_ops.args, args, nargs * sizeof(*args));

	ret = BPF_CGROUP_RUN_PROG_SOCK_OPS(&sock_ops);
	if (ret == 0)
		ret = sock_ops.reply;
	else
		ret = -1;
	return ret;
}

static inline int tcp_call_bpf_2arg(struct sock *sk, int op, u32 arg1, u32 arg2)
{
	u32 args[2] = {arg1, arg2};

	return tcp_call_bpf(sk, op, 2, args);
}

static inline int tcp_call_bpf_3arg(struct sock *sk, int op, u32 arg1, u32 arg2,
				    u32 arg3)
{
	u32 args[3] = {arg1, arg2, arg3};

	return tcp_call_bpf(sk, op, 3, args);
}

#else
static inline int tcp_call_bpf(struct sock *sk, int op, u32 nargs, u32 *args)
{
	return -EPERM;
}

static inline int tcp_call_bpf_2arg(struct sock *sk, int op, u32 arg1, u32 arg2)
{
	return -EPERM;
}

static inline int tcp_call_bpf_3arg(struct sock *sk, int op, u32 arg1, u32 arg2,
				    u32 arg3)
{
	return -EPERM;
}

#endif

static inline u32 tcp_timeout_init(struct sock *sk)
{
	int timeout;

	timeout = tcp_call_bpf(sk, BPF_SOCK_OPS_TIMEOUT_INIT, 0, NULL);

	if (timeout <= 0)
		timeout = TCP_TIMEOUT_INIT;
	return timeout;
}

static inline u32 tcp_rwnd_init_bpf(struct sock *sk)
{
	int rwnd;

	rwnd = tcp_call_bpf(sk, BPF_SOCK_OPS_RWND_INIT, 0, NULL);

	if (rwnd < 0)
		rwnd = 0;
	return rwnd;
}

static inline bool tcp_bpf_ca_needs_ecn(struct sock *sk)
{
	return (tcp_call_bpf(sk, BPF_SOCK_OPS_NEEDS_ECN, 0, NULL) == 1);
}

static inline void tcp_bpf_rtt(struct sock *sk)
{
	if (BPF_SOCK_OPS_TEST_FLAG(tcp_sk(sk), BPF_SOCK_OPS_RTT_CB_FLAG))
		tcp_call_bpf(sk, BPF_SOCK_OPS_RTT_CB, 0, NULL);
}


#endif	/* _TCP_BPF_H */
