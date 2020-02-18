// SPDX-License-Identifier: GPL-2.0
/* Filesystem information for NFS
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/nfs_fs.h>
#include <linux/windows.h>
#include "internal.h"

static const struct fsinfo_timestamp_info nfs_timestamp_info = {
	.atime = {
		.minimum	= 0,
		.maximum	= UINT_MAX,
		.gran_mantissa	= 1,
		.gran_exponent	= 0,
	},
	.mtime = {
		.minimum	= 0,
		.maximum	= UINT_MAX,
		.gran_mantissa	= 1,
		.gran_exponent	= 0,
	},
	.ctime = {
		.minimum	= 0,
		.maximum	= UINT_MAX,
		.gran_mantissa	= 1,
		.gran_exponent	= 0,
	},
	.btime = {
		.minimum	= 0,
		.maximum	= UINT_MAX,
		.gran_mantissa	= 1,
		.gran_exponent	= 0,
	},
};

static int nfs_fsinfo_get_timestamp_info(struct path *path, struct fsinfo_context *ctx)
{
	const struct nfs_server *server = NFS_SB(path->dentry->d_sb);
	struct fsinfo_timestamp_info *r = ctx->buffer;
	unsigned long long nsec;
	unsigned int rem, mant;
	int exp = -9;

	*r = nfs_timestamp_info;

	nsec = server->time_delta.tv_nsec;
	nsec += server->time_delta.tv_sec * 1000000000ULL;
	if (nsec == 0)
		goto out;

	do {
		mant = nsec;
		rem = do_div(nsec, 10);
		if (rem)
			break;
		exp++;
	} while (nsec);

	r->atime.gran_mantissa = mant;
	r->atime.gran_exponent = exp;
	r->btime.gran_mantissa = mant;
	r->btime.gran_exponent = exp;
	r->ctime.gran_mantissa = mant;
	r->ctime.gran_exponent = exp;
	r->mtime.gran_mantissa = mant;
	r->mtime.gran_exponent = exp;

out:
	return sizeof(*r);
}

static int nfs_fsinfo_get_info(struct path *path, struct fsinfo_context *ctx)
{
	const struct nfs_server *server = NFS_SB(path->dentry->d_sb);
	const struct nfs_client *clp = server->nfs_client;
	struct fsinfo_nfs_info *r = ctx->buffer;

	r->version		= clp->rpc_ops->version;
	r->minor_version	= clp->cl_minorversion;
	r->transport_proto	= clp->cl_proto;
	return sizeof(*r);
}

static int nfs_fsinfo_get_server_name(struct path *path, struct fsinfo_context *ctx)
{
	const struct nfs_server *server = NFS_SB(path->dentry->d_sb);
	const struct nfs_client *clp = server->nfs_client;

	return fsinfo_string(clp->cl_hostname, ctx);
}

static int nfs_fsinfo_get_server_addresses(struct path *path, struct fsinfo_context *ctx)
{
	const struct nfs_server *server = NFS_SB(path->dentry->d_sb);
	const struct nfs_client *clp = server->nfs_client;
	struct fsinfo_nfs_server_address *addr = ctx->buffer;
	int ret;

	ret = 1 * sizeof(*addr);
	if (ret <= ctx->buf_size)
		memcpy(&addr[0].address, &clp->cl_addr, clp->cl_addrlen);
	return ret;

}

static int nfs_fsinfo_get_gssapi_name(struct path *path, struct fsinfo_context *ctx)
{
	const struct nfs_server *server = NFS_SB(path->dentry->d_sb);
	const struct nfs_client *clp = server->nfs_client;

	return fsinfo_string(clp->cl_acceptor, ctx);
}

static int nfs_fsinfo_get_limits(struct path *path, struct fsinfo_context *ctx)
{
	const struct nfs_server *server = NFS_SB(path->dentry->d_sb);
	struct fsinfo_limits *lim = ctx->buffer;

	lim->max_file_size.hi	= 0;
	lim->max_file_size.lo	= server->maxfilesize;
	lim->max_ino.hi		= 0;
	lim->max_ino.lo		= U64_MAX;
	lim->max_hard_links	= UINT_MAX;
	lim->max_uid		= UINT_MAX;
	lim->max_gid		= UINT_MAX;
	lim->max_filename_len	= NAME_MAX - 1;
	lim->max_symlink_len	= PATH_MAX - 1;
	return sizeof(*lim);
}

static int nfs_fsinfo_get_supports(struct path *path, struct fsinfo_context *ctx)
{
	const struct nfs_server *server = NFS_SB(path->dentry->d_sb);
	struct fsinfo_supports *sup = ctx->buffer;

	/* Don't set STATX_INO as i_ino is fabricated and may not be unique. */

	if (!(server->caps & NFS_CAP_MODE))
		sup->stx_mask |= STATX_TYPE | STATX_MODE;
	if (server->caps & NFS_CAP_OWNER)
		sup->stx_mask |= STATX_UID;
	if (server->caps & NFS_CAP_OWNER_GROUP)
		sup->stx_mask |= STATX_GID;
	if (server->caps & NFS_CAP_ATIME)
		sup->stx_mask |= STATX_ATIME;
	if (server->caps & NFS_CAP_CTIME)
		sup->stx_mask |= STATX_CTIME;
	if (server->caps & NFS_CAP_MTIME)
		sup->stx_mask |= STATX_MTIME;
	if (server->attr_bitmask[0] & FATTR4_WORD0_SIZE)
		sup->stx_mask |= STATX_SIZE;
	if (server->attr_bitmask[1] & FATTR4_WORD1_NUMLINKS)
		sup->stx_mask |= STATX_NLINK;

	if (server->attr_bitmask[0] & FATTR4_WORD0_ARCHIVE)
		sup->win_file_attrs |= ATTR_ARCHIVE;
	if (server->attr_bitmask[0] & FATTR4_WORD0_HIDDEN)
		sup->win_file_attrs |= ATTR_HIDDEN;
	if (server->attr_bitmask[1] & FATTR4_WORD1_SYSTEM)
		sup->win_file_attrs |= ATTR_SYSTEM;

	sup->stx_attributes = STATX_ATTR_AUTOMOUNT;
	return sizeof(*sup);
}

static int nfs_fsinfo_get_features(struct path *path, struct fsinfo_context *ctx)
{
	const struct nfs_server *server = NFS_SB(path->dentry->d_sb);
	struct fsinfo_features *ft = ctx->buffer;

	fsinfo_set_feature(ft, FSINFO_FEAT_IS_NETWORK_FS);
	fsinfo_set_feature(ft, FSINFO_FEAT_AUTOMOUNTS);
	fsinfo_set_feature(ft, FSINFO_FEAT_O_SYNC);
	fsinfo_set_feature(ft, FSINFO_FEAT_O_DIRECT);
	fsinfo_set_feature(ft, FSINFO_FEAT_ADV_LOCKS);
	fsinfo_set_feature(ft, FSINFO_FEAT_DEVICE_FILES);
	fsinfo_set_feature(ft, FSINFO_FEAT_UNIX_SPECIALS);
	if (server->nfs_client->rpc_ops->version == 4) {
		fsinfo_set_feature(ft, FSINFO_FEAT_LEASES);
		fsinfo_set_feature(ft, FSINFO_FEAT_IVER_ALL_CHANGE);
	}

	if (server->caps & NFS_CAP_OWNER)
		fsinfo_set_feature(ft, FSINFO_FEAT_UIDS);
	if (server->caps & NFS_CAP_OWNER_GROUP)
		fsinfo_set_feature(ft, FSINFO_FEAT_GIDS);
	if (!(server->caps & NFS_CAP_MODE))
		fsinfo_set_feature(ft, FSINFO_FEAT_NO_UNIX_MODE);
	if (server->caps & NFS_CAP_ACLS)
		fsinfo_set_feature(ft, FSINFO_FEAT_HAS_ACL);
	if (server->caps & NFS_CAP_SYMLINKS)
		fsinfo_set_feature(ft, FSINFO_FEAT_SYMLINKS);
	if (server->caps & NFS_CAP_HARDLINKS)
		fsinfo_set_feature(ft, FSINFO_FEAT_HARD_LINKS);
	if (server->caps & NFS_CAP_ATIME)
		fsinfo_set_feature(ft, FSINFO_FEAT_HAS_ATIME);
	if (server->caps & NFS_CAP_CTIME)
		fsinfo_set_feature(ft, FSINFO_FEAT_HAS_CTIME);
	if (server->caps & NFS_CAP_MTIME)
		fsinfo_set_feature(ft, FSINFO_FEAT_HAS_MTIME);

	if (server->attr_bitmask[0] & FATTR4_WORD0_CASE_INSENSITIVE)
		fsinfo_set_feature(ft, FSINFO_FEAT_NAME_CASE_INDEP);
	if ((server->attr_bitmask[0] & FATTR4_WORD0_ARCHIVE) ||
	    (server->attr_bitmask[0] & FATTR4_WORD0_HIDDEN) ||
	    (server->attr_bitmask[1] & FATTR4_WORD1_SYSTEM))
		fsinfo_set_feature(ft, FSINFO_FEAT_WINDOWS_ATTRS);

	return sizeof(*ft);
}

static const struct fsinfo_attribute nfs_fsinfo_attributes[] = {
	FSINFO_VSTRUCT	(FSINFO_ATTR_TIMESTAMP_INFO,	nfs_fsinfo_get_timestamp_info),
	FSINFO_VSTRUCT	(FSINFO_ATTR_LIMITS,		nfs_fsinfo_get_limits),
	FSINFO_VSTRUCT	(FSINFO_ATTR_SUPPORTS,		nfs_fsinfo_get_supports),
	FSINFO_VSTRUCT	(FSINFO_ATTR_FEATURES,		nfs_fsinfo_get_features),
	FSINFO_VSTRUCT	(FSINFO_ATTR_NFS_INFO,		nfs_fsinfo_get_info),
	FSINFO_STRING	(FSINFO_ATTR_NFS_SERVER_NAME,	nfs_fsinfo_get_server_name),
	FSINFO_LIST	(FSINFO_ATTR_NFS_SERVER_ADDRESSES, nfs_fsinfo_get_server_addresses),
	FSINFO_STRING	(FSINFO_ATTR_NFS_GSSAPI_NAME,	nfs_fsinfo_get_gssapi_name),
	{}
};

int nfs_fsinfo(struct path *path, struct fsinfo_context *ctx)
{
	return fsinfo_get_attribute(path, ctx, nfs_fsinfo_attributes);
}
