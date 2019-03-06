// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Mellanox Technologies. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <uapi/linux/btf.h>
#include "en.h"
#include "en/xdp.h"

/* BTF */

#define BTF_INFO_ENC(kind, kind_flag, vlen)			\
	((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))

#define BTF_TYPE_ENC(name, info, size_or_type)	\
	(name), (info), (size_or_type)

#define BTF_INT_ENC(encoding, bits_offset, nr_bits)	\
	((encoding) << 24 | (bits_offset) << 16 | (nr_bits))

#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz)	\
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz),	\
	BTF_INT_ENC(encoding, bits_offset, bits)

#define BTF_STRUCT_ENC(name, nr_elems, sz)	\
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_STRUCT, 1, nr_elems), sz)

#define BTF_MEMBER_ENC(name, type, bits_offset)	\
	(name), (type), (bits_offset)

/* struct xdp_md_desc {
 *	u32 flow_mark;
 *	u32 hash32;
 * };
 */
#define MLX5_MD_NUM_MMBRS 2
static const char names_str[] = "\0xdp_md_desc\0flow_mark\0hash32\0";

/* Must match struct mlx5_md_desc */
static const u32 mlx5_md_raw_types[] = {
	/* #define u32 */
	BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),         /* type [1] */
	/* struct md_desc { */                    /* type [2] */
	BTF_STRUCT_ENC(1, MLX5_MD_NUM_MMBRS, MLX5_MD_NUM_MMBRS * 4),
		BTF_MEMBER_ENC(13, 1, 0),    /* u32 flow_mark;    */
		BTF_MEMBER_ENC(23, 1, 32),  /* u32 hash32;       */
	/* } */
};

/* XDP btf is registered once only 1st time xdp md setup/query is called */
static int mlx5e_xdp_register_btf(struct mlx5e_priv *priv)
{
	unsigned int type_sec_sz, str_sec_sz;
	char *types_sec, *str_sec;
	struct btf_header *hdr;
	unsigned int btf_size;
	void *raw_btf = NULL;
	int err = 0;

	type_sec_sz = sizeof(mlx5_md_raw_types);
	str_sec_sz  = sizeof(names_str);

	btf_size = sizeof(*hdr) + type_sec_sz + str_sec_sz;
	raw_btf = kzalloc(btf_size, GFP_KERNEL);
	if (!raw_btf)
		return -ENOMEM;

	hdr = raw_btf;
	hdr->magic    = BTF_MAGIC;
	hdr->version  = BTF_VERSION;
	hdr->hdr_len  = sizeof(*hdr);
	hdr->type_off = 0;
	hdr->type_len = type_sec_sz;
	hdr->str_off  = type_sec_sz;
	hdr->str_len  = str_sec_sz;

	types_sec = raw_btf   + sizeof(*hdr);
	str_sec   = types_sec + type_sec_sz;
	memcpy(types_sec, mlx5_md_raw_types, type_sec_sz);
	memcpy(str_sec, names_str, str_sec_sz);

	priv->xdp.btf = btf_register(raw_btf, btf_size);
	if (IS_ERR(priv->xdp.btf)) {
		err = PTR_ERR(priv->xdp.btf);
		priv->xdp.btf = NULL;
		netdev_err(priv->netdev, "failed to register BTF MD, err (%d)\n", err);
	}

	kfree(raw_btf);
	return err;
}

static void mlx5e_xdp_set_rqs_md(struct mlx5e_priv *priv)
{
	int i;

	for (i = 0; i < priv->channels.num ; i++) {
		struct mlx5e_rq *rq  = &priv->channels.c[i]->rq;
		u8 btf_enabled = priv->xdp.btf_enabled;

		btf_enabled ? set_bit(MLX5e_RQ_FLAG_XDP_MD,   rq->flags) :
			      clear_bit(MLX5e_RQ_FLAG_XDP_MD, rq->flags);
	}
}

int mlx5e_xdp_set_btf_md(struct net_device *dev, u8 enable)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int err = 0;

	mutex_lock(&priv->state_lock);

	if (enable && !priv->xdp.btf) {
		mlx5e_xdp_register_btf(priv);
		if (!priv->xdp.btf) {
			err = -EINVAL;
			goto unlock;
		}
	}

	priv->xdp.btf_enabled = enable;
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_xdp_set_rqs_md(priv);

unlock:
	mutex_unlock(&priv->state_lock);
	return err;
}

int mlx5e_xdp_query_btf(struct net_device *dev, u8 *enabled)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	u32 md_btf_id = 0;

	if (!IS_ENABLED(CONFIG_BPF_SYSCALL))
		return md_btf_id;

	mutex_lock(&priv->state_lock);

	if (!priv->xdp.btf)
		mlx5e_xdp_register_btf(priv);

	*enabled = !!priv->xdp.btf_enabled;
	md_btf_id = priv->xdp.btf ? btf_id(priv->xdp.btf) : 0;

	mutex_unlock(&priv->state_lock);
	return md_btf_id;
}

void mlx5e_xdp_cleanup(struct mlx5e_priv *priv)
{
	if (priv->xdp.btf)
		btf_unregister(priv->xdp.btf);
	priv->xdp.btf = NULL;
}
