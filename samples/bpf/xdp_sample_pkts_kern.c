// SPDX-License-Identifier: GPL-2.0
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define SAMPLE_SIZE 64ul
#define MAX_CPUS 128

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(u32),
	.max_entries = MAX_CPUS,
};

SEC("xdp_sample")
int xdp_sample_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Metadata will be in the perf event before the packet data. */
	struct S {
		u16 cookie;
		u16 pkt_len;
	} __packed metadata;

	if (data < data_end) {
		/* The XDP perf_event_output handler will use the upper 32 bits
		 * of the flags argument as a number of bytes to include of the
		 * packet payload in the event data. If the size is too big, the
		 * call to bpf_perf_event_output will fail and return -EFAULT.
		 *
		 * See bpf_xdp_event_output in net/core/filter.c.
		 *
		 * The BPF_F_CURRENT_CPU flag means that the event output fd
		 * will be indexed by the CPU number in the event map.
		 */
		u64 flags = BPF_F_CURRENT_CPU;
		u16 sample_size;
		int ret;

		metadata.cookie = 0xdead;
		metadata.pkt_len = (u16)(data_end - data);
		sample_size = min(metadata.pkt_len, SAMPLE_SIZE);
		flags |= (u64)sample_size << 32;

		ret = bpf_perf_event_output(ctx, &my_map, flags,
					    &metadata, sizeof(metadata));
		if (ret)
			bpf_printk("perf_event_output failed: %d\n", ret);
	}

	return XDP_PASS;
}

#ifdef XDP_MD_BTF
/* xdp_md_btf.h is normally generated via bpftool */
#include "xdp_md_btf.h"

SEC("xdp_sample_md")
int xdp_sample_md_prog(struct xdp_md *ctx)
{
	struct xdp_md_desc *md = (void *)(long)ctx->data_meta;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct xdp_md_desc metadata = {};

	if (data < data_end) {
		u64 flags = BPF_F_CURRENT_CPU;
		u16 sample_size;
		int ret;

		if (md + 1 <= data) /* copy metadata from driver */
			metadata = *md;

		sample_size = (u16)(data_end - data);
		sample_size = min(sample_size, SAMPLE_SIZE);
		flags |= (u64)sample_size << 32;

		ret = bpf_perf_event_output(ctx, &my_map, flags,
					    &metadata, sizeof(metadata));
		if (ret)
			bpf_printk("perf_event_output failed: %d\n", ret);
	}

	return XDP_PASS;
}
#endif

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
