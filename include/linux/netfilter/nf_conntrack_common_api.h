/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_CONNTRACK_COMMON_API_H
#define _NF_CONNTRACK_COMMON_API_H

#include <linux/netfilter/nf_conntrack_common.h>

#include <linux/refcount_api.h>

void nf_conntrack_destroy(struct nf_conntrack *nfct);

/* like nf_ct_put, but without module dependency on nf_conntrack */
static inline void nf_conntrack_put(struct nf_conntrack *nfct)
{
	if (nfct && refcount_dec_and_test(&nfct->use))
		nf_conntrack_destroy(nfct);
}
static inline void nf_conntrack_get(struct nf_conntrack *nfct)
{
	if (nfct)
		refcount_inc(&nfct->use);
}

#endif /* _NF_CONNTRACK_COMMON_API_H */
