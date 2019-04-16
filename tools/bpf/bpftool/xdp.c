// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (C) 2019 Mellanox.

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <uapi/linux/btf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include "bpf/libbpf_internal.h"
#include "bpf/nlattr.h"
#include "main.h"
#include "netlink_dumper.h"

struct ip_devname_ifindex {
	char	devname[64];
	int	ifindex;
};

struct bpf_netdev_t {
	struct ip_devname_ifindex *devices;
	int	used_len;
	int	array_len;
	int	filter_idx;
};

static int do_show(int argc, char **argv)
{
	int sock, ret, filter_idx = -1;
	struct bpf_netdev_t dev_array;
	unsigned int nl_pid;
	char err_buf[256];

	if (argc == 2) {
		if (strcmp(argv[0], "dev") != 0)
			usage();
		filter_idx = if_nametoindex(argv[1]);
		if (filter_idx == 0) {
			fprintf(stderr, "invalid dev name %s\n", argv[1]);
			return -1;
		}
	} else if (argc != 0) {
		usage();
	}

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0) {
		fprintf(stderr, "failed to open netlink sock\n");
		return -1;
	}

	dev_array.devices = NULL;
	dev_array.used_len = 0;
	dev_array.array_len = 0;
	dev_array.filter_idx = filter_idx;

	if (json_output)
		jsonw_start_array(json_wtr);
	NET_START_OBJECT;
	NET_START_ARRAY("xdp", "%s:\n");
	ret = libbpf_nl_get_link(sock, nl_pid, xdp_dump_link_nlmsg, &dev_array);
	NET_END_ARRAY("\n");

	NET_END_OBJECT;
	if (json_output)
		jsonw_end_array(json_wtr);

	if (ret) {
		if (json_output)
			jsonw_null(json_wtr);
		libbpf_strerror(ret, err_buf, sizeof(err_buf));
		fprintf(stderr, "Error: %s\n", err_buf);
	}
	free(dev_array.devices);
	close(sock);
	return ret;
}

static int set_usage(void)
{
	fprintf(stderr,
		"Usage: %s net xdp set dev <devname> {md_btf {on|off}}\n"
		"       %s net xdp set help\n"
		"       md_btf {on|off}: enable/disable meta data btf\n",
		bin_name, bin_name);

	return -1;
}

static int xdp_set_md_btf(int ifindex, char *arg)
{
	__u8 enable = (strcmp(arg, "on") == 0) ? 1 : 0;
	int ret;

	ret = bpf_set_link_xdp_md_btf(ifindex, enable);
	if (ret)
		fprintf(stderr, "Failed to setup xdp md, err=%d\n", ret);

	return -ret;
}

static int do_set(int argc, char **argv)
{
	char *set_cmd, *set_arg;
	int dev_idx = -1;

	if (argc < 4)
		return set_usage();

	if (strcmp(argv[0], "dev") != 0)
		return set_usage();

	dev_idx = if_nametoindex(argv[1]);
	if (dev_idx == 0) {
		fprintf(stderr, "invalid dev name %s\n", argv[1]);
		return -1;
	}

	set_cmd = argv[2];
	set_arg = argv[3];

	if (strcmp(set_cmd, "md_btf") != 0)
		return set_usage();

	if (strcmp(set_arg, "on") != 0 && strcmp(set_arg, "off") != 0)
		return set_usage();

	return xdp_set_md_btf(dev_idx, set_arg);
}

struct xdp_btf_attr {
	int ifindex;
	__u8 enabled;
	__u32 id;
};

static int xdp_btf_attr_link_nlmsg(void *cookie, void *msg, struct nlattr **tb)
{
	struct nlattr *xdp_tb[IFLA_XDP_MAX + 1];
	struct xdp_btf_attr *attr = cookie;
	struct ifinfomsg *ifinfo = msg;

	if (attr->ifindex != ifinfo->ifi_index)
		return 0;

	if (!tb[IFLA_XDP])
		return -1;

	if (libbpf_nla_parse_nested(xdp_tb, IFLA_XDP_MAX, tb[IFLA_XDP], NULL) < 0)
		return -1;

	if (!xdp_tb[IFLA_XDP_MD_BTF_ID])
		return 0;

	attr->id = libbpf_nla_getattr_u32(xdp_tb[IFLA_XDP_MD_BTF_ID]);
	attr->enabled = libbpf_nla_getattr_u8(xdp_tb[IFLA_XDP_MD_BTF_STATE]);
	return 0;
}

static int xdp_netlink_get_btf_attr(struct xdp_btf_attr *attr)
{
	unsigned int nl_pid;
	char err_buf[256];
	int sock, ret;

	sock = libbpf_netlink_open(&nl_pid);
	if (sock < 0) {
		fprintf(stderr, "failed to open netlink sock\n");
		return -1;
	}

	ret = libbpf_nl_get_link(sock, nl_pid, xdp_btf_attr_link_nlmsg, attr);
	if (ret) {
		libbpf_strerror(ret, err_buf, sizeof(err_buf));
		fprintf(stderr, "Error: %s\n", err_buf);
	}

	close(sock);
	return ret;
}

static int dump_btf_usage(void)
{
	fprintf(stderr,
		"Usage: %s net xdp md_btf cstyle dev <devname>\n"
		"       %s net xdp md_btf help\n"
		"       dump XDP meta data btf of a device in c style format\n",
		bin_name, bin_name);

	return -1;
}

static int do_md_btf(int argc, char **argv)
{
	struct xdp_btf_attr attr = {};
	struct btf *btf = NULL;
	char *dev_name;
	int ret;

	if (argc < 3)
		return dump_btf_usage();

	if (strcmp(argv[0], "cstyle") != 0)
		return dump_btf_usage();

	dev_name = argv[2];
	if (strcmp(argv[1], "dev") != 0)
		return dump_btf_usage();

	attr.ifindex = if_nametoindex(dev_name);
	if (attr.ifindex == 0) {
		fprintf(stderr, "invalid dev name %s\n", dev_name);
		return -1;
	}
	ret = xdp_netlink_get_btf_attr(&attr);
	if (ret)
		return ret;

	fprintf(stdout, "//XDP BTF: %s(%d) id(%d) enabled(%d)\n\n",
		argv[1], attr.ifindex, attr.id, attr.enabled);

	ret = btf__get_from_id(attr.id, &btf);
	if (ret || !btf) {
		fprintf(stderr, "Failed to get btf from id err=%d, btf %p\n", ret, btf);
		return -1;
	}

	fprintf(stdout, "#ifndef __XDP_MD_BTF_%s\n", dev_name);
	fprintf(stdout, "#define __XDP_MD_BTF_%s\n\n", dev_name);

	ret = btf_dump_c_format(btf);

	fprintf(stdout, "\n#endif /* __XDP_MD_BTF_%s */\n\n", dev_name);
	btf__free(btf);
	return ret;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %s %s xdp { show | list | set | md_btf} [dev <devname>]\n"
		"       %s %s help\n",
		bin_name, argv[-2], bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",        do_show },
	{ "list",        do_show },
	{ "set",         do_set  },
	{ "md_btf",      do_md_btf },
	{ "help",        do_help },
	{ 0 }
};

int do_xdp(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
