/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_SKBUFF_API_EXTRA_H
#define _LINUX_SKBUFF_API_EXTRA_H

#include <linux/skbuff_api.h>

#include <net/checksum.h>

static inline bool skb_flow_dissect_flow_keys(const struct sk_buff *skb,
					      struct flow_keys *flow,
					      unsigned int flags)
{
	memset(flow, 0, sizeof(*flow));
	return __skb_flow_dissect(NULL, skb, &flow_keys_dissector,
				  flow, NULL, 0, 0, 0, flags);
}

static inline bool
skb_flow_dissect_flow_keys_basic(const struct net *net,
				 const struct sk_buff *skb,
				 struct flow_keys_basic *flow,
				 const void *data, __be16 proto,
				 int nhoff, int hlen, unsigned int flags)
{
	memset(flow, 0, sizeof(*flow));
	return __skb_flow_dissect(net, skb, &flow_keys_basic_dissector, flow,
				  data, proto, nhoff, hlen, flags);
}

static inline void *__skb_put_zero(struct sk_buff *skb, unsigned int len)
{
	void *tmp = __skb_put(skb, len);

	memset(tmp, 0, len);
	return tmp;
}

static inline void *__skb_put_data(struct sk_buff *skb, const void *data,
				   unsigned int len)
{
	void *tmp = __skb_put(skb, len);

	memcpy(tmp, data, len);
	return tmp;
}

static inline void *skb_put_zero(struct sk_buff *skb, unsigned int len)
{
	void *tmp = skb_put(skb, len);

	memset(tmp, 0, len);

	return tmp;
}

static inline void *skb_put_data(struct sk_buff *skb, const void *data,
				 unsigned int len)
{
	void *tmp = skb_put(skb, len);

	memcpy(tmp, data, len);

	return tmp;
}

static inline void skb_probe_transport_header(struct sk_buff *skb)
{
	struct flow_keys_basic keys;

	if (skb_transport_header_was_set(skb))
		return;

	if (skb_flow_dissect_flow_keys_basic(NULL, skb, &keys,
					     NULL, 0, 0, 0, 0))
		skb_set_transport_header(skb, keys.control.thoff);
}

static inline void skb_mac_header_rebuild(struct sk_buff *skb)
{
	if (skb_mac_header_was_set(skb)) {
		const unsigned char *old_mac = skb_mac_header(skb);

		skb_set_mac_header(skb, -skb->mac_len);
		memmove(skb_mac_header(skb), old_mac, skb->mac_len);
	}
}

static inline int skb_add_data(struct sk_buff *skb,
			       struct iov_iter *from, int copy)
{
	const int off = skb->len;

	if (skb->ip_summed == CHECKSUM_NONE) {
		__wsum csum = 0;
		if (csum_and_copy_from_iter_full(skb_put(skb, copy), copy,
					         &csum, from)) {
			skb->csum = csum_block_add(skb->csum, csum, off);
			return 0;
		}
	} else if (copy_from_iter_full(skb_put(skb, copy), copy, from))
		return 0;

	__skb_trim(skb, off);
	return -EFAULT;
}

static __always_inline void
__skb_postpull_rcsum(struct sk_buff *skb, const void *start, unsigned int len,
		     unsigned int off)
{
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_block_sub(skb->csum,
					   csum_partial(start, len, 0), off);
	else if (skb->ip_summed == CHECKSUM_PARTIAL &&
		 skb_checksum_start_offset(skb) < 0)
		skb->ip_summed = CHECKSUM_NONE;
}

/**
 *	skb_postpull_rcsum - update checksum for received skb after pull
 *	@skb: buffer to update
 *	@start: start of data before pull
 *	@len: length of data pulled
 *
 *	After doing a pull on a received packet, you need to call this to
 *	update the CHECKSUM_COMPLETE checksum, or set ip_summed to
 *	CHECKSUM_NONE so that it can be recomputed from scratch.
 */
static inline void skb_postpull_rcsum(struct sk_buff *skb,
				      const void *start, unsigned int len)
{
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = wsum_negate(csum_partial(start, len,
						     wsum_negate(skb->csum)));
	else if (skb->ip_summed == CHECKSUM_PARTIAL &&
		 skb_checksum_start_offset(skb) < 0)
		skb->ip_summed = CHECKSUM_NONE;
}

static __always_inline void
__skb_postpush_rcsum(struct sk_buff *skb, const void *start, unsigned int len,
		     unsigned int off)
{
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_block_add(skb->csum,
					   csum_partial(start, len, 0), off);
}

/**
 *	skb_postpush_rcsum - update checksum for received skb after push
 *	@skb: buffer to update
 *	@start: start of data after push
 *	@len: length of data pushed
 *
 *	After doing a push on a received packet, you need to call this to
 *	update the CHECKSUM_COMPLETE checksum.
 */
static inline void skb_postpush_rcsum(struct sk_buff *skb,
				      const void *start, unsigned int len)
{
	__skb_postpush_rcsum(skb, start, len, 0);
}

/**
 *	skb_push_rcsum - push skb and update receive checksum
 *	@skb: buffer to update
 *	@len: length of data pulled
 *
 *	This function performs an skb_push on the packet and updates
 *	the CHECKSUM_COMPLETE checksum.  It should be used on
 *	receive path processing instead of skb_push unless you know
 *	that the checksum difference is zero (e.g., a valid IP header)
 *	or you are setting ip_summed to CHECKSUM_NONE.
 */
static inline void *skb_push_rcsum(struct sk_buff *skb, unsigned int len)
{
	skb_push(skb, len);
	skb_postpush_rcsum(skb, skb->data, len);
	return skb->data;
}

static inline void skb_copy_from_linear_data(const struct sk_buff *skb,
					     void *to,
					     const unsigned int len)
{
	memcpy(to, skb->data, len);
}

static inline void skb_copy_from_linear_data_offset(const struct sk_buff *skb,
						    const int offset, void *to,
						    const unsigned int len)
{
	memcpy(to, skb->data + offset, len);
}

static inline void skb_copy_to_linear_data(struct sk_buff *skb,
					   const void *from,
					   const unsigned int len)
{
	memcpy(skb->data, from, len);
}

static inline void skb_copy_to_linear_data_offset(struct sk_buff *skb,
						  const int offset,
						  const void *from,
						  const unsigned int len)
{
	memcpy(skb->data + offset, from, len);
}

/* Validate (init) checksum based on checksum complete.
 *
 * Return values:
 *   0: checksum is validated or try to in skb_checksum_complete. In the latter
 *	case the ip_summed will not be CHECKSUM_UNNECESSARY and the pseudo
 *	checksum is stored in skb->csum for use in __skb_checksum_complete
 *   non-zero: value of invalid checksum
 *
 */
static inline __sum16 __skb_checksum_validate_complete(struct sk_buff *skb,
						       bool complete,
						       __wsum psum)
{
	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!csum_fold(csum_add(psum, skb->csum))) {
			skb->csum_valid = 1;
			return 0;
		}
	}

	skb->csum = psum;

	if (complete || skb->len <= CHECKSUM_BREAK) {
		__sum16 csum;

		csum = __skb_checksum_complete(skb);
		skb->csum_valid = !csum;
		return csum;
	}

	return 0;
}

static inline void gso_reset_checksum(struct sk_buff *skb, __wsum res)
{
	/* Do not update partial checksums if remote checksum is enabled. */
	if (skb->remcsum_offload)
		return;

	SKB_GSO_CB(skb)->csum = res;
	SKB_GSO_CB(skb)->csum_start = skb_checksum_start(skb) - skb->head;
}

/* Compute the checksum for a gso segment. First compute the checksum value
 * from the start of transport header to SKB_GSO_CB(skb)->csum_start, and
 * then add in skb->csum (checksum from csum_start to end of packet).
 * skb->csum and csum_start are then updated to reflect the checksum of the
 * resultant packet starting from the transport header-- the resultant checksum
 * is in the res argument (i.e. normally zero or ~ of checksum of a pseudo
 * header.
 */
static inline __sum16 gso_make_checksum(struct sk_buff *skb, __wsum res)
{
	unsigned char *csum_start = skb_transport_header(skb);
	int plen = (skb->head + SKB_GSO_CB(skb)->csum_start) - csum_start;
	__wsum partial = SKB_GSO_CB(skb)->csum;

	SKB_GSO_CB(skb)->csum = res;
	SKB_GSO_CB(skb)->csum_start = csum_start - skb->head;

	return csum_fold(csum_partial(csum_start, plen, partial));
}

/* Local Checksum Offload.
 * Compute outer checksum based on the assumption that the
 * inner checksum will be offloaded later.
 * See Documentation/networking/checksum-offloads.rst for
 * explanation of how this works.
 * Fill in outer checksum adjustment (e.g. with sum of outer
 * pseudo-header) before calling.
 * Also ensure that inner checksum is in linear data area.
 */
static inline __wsum lco_csum(struct sk_buff *skb)
{
	unsigned char *csum_start = skb_checksum_start(skb);
	unsigned char *l4_hdr = skb_transport_header(skb);
	__wsum partial;

	/* Start with complement of inner checksum adjustment */
	partial = ~csum_unfold(*(__force __sum16 *)(csum_start +
						    skb->csum_offset));

	/* Add in checksum of our headers (incl. outer checksum
	 * adjustment filled in by caller) and return result.
	 */
	return csum_partial(l4_hdr, csum_start - l4_hdr, partial);
}

/* Perform checksum validate (init). Note that this is a macro since we only
 * want to calculate the pseudo header which is an input function if necessary.
 * First we try to validate without any computation (checksum unnecessary) and
 * then calculate based on checksum complete calling the function to compute
 * pseudo header.
 *
 * Return values:
 *   0: checksum is validated or try to in skb_checksum_complete
 *   non-zero: value of invalid checksum
 */
#define __skb_checksum_validate(skb, proto, complete,			\
				zero_okay, check, compute_pseudo)	\
({									\
	__sum16 __ret = 0;						\
	skb->csum_valid = 0;						\
	if (__skb_checksum_validate_needed(skb, zero_okay, check))	\
		__ret = __skb_checksum_validate_complete(skb,		\
				complete, compute_pseudo(skb, proto));	\
	__ret;								\
})

#define skb_checksum_init(skb, proto, compute_pseudo)			\
	__skb_checksum_validate(skb, proto, false, false, 0, compute_pseudo)

#define skb_checksum_init_zero_check(skb, proto, check, compute_pseudo)	\
	__skb_checksum_validate(skb, proto, false, true, check, compute_pseudo)

#define skb_checksum_validate(skb, proto, compute_pseudo)		\
	__skb_checksum_validate(skb, proto, true, false, 0, compute_pseudo)

#define skb_checksum_validate_zero_check(skb, proto, check,		\
					 compute_pseudo)		\
	__skb_checksum_validate(skb, proto, true, true, check, compute_pseudo)

#define skb_checksum_simple_validate(skb)				\
	__skb_checksum_validate(skb, 0, true, false, 0, null_compute_pseudo)

static inline bool __skb_checksum_convert_check(struct sk_buff *skb)
{
	return (skb->ip_summed == CHECKSUM_NONE && skb->csum_valid);
}

static inline void __skb_checksum_convert(struct sk_buff *skb, __wsum pseudo)
{
	skb->csum = ~pseudo;
	skb->ip_summed = CHECKSUM_COMPLETE;
}

#define skb_checksum_try_convert(skb, proto, compute_pseudo)	\
do {									\
	if (__skb_checksum_convert_check(skb))				\
		__skb_checksum_convert(skb, compute_pseudo(skb, proto)); \
} while (0)

static inline void skb_remcsum_adjust_partial(struct sk_buff *skb, void *ptr,
					      u16 start, u16 offset)
{
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = ((unsigned char *)ptr + start) - skb->head;
	skb->csum_offset = offset - start;
}

/* Update skbuf and packet to reflect the remote checksum offload operation.
 * When called, ptr indicates the starting point for skb->csum when
 * ip_summed is CHECKSUM_COMPLETE. If we need create checksum complete
 * here, skb_postpull_rcsum is done so skb->csum start is ptr.
 */
static inline void skb_remcsum_process(struct sk_buff *skb, void *ptr,
				       int start, int offset, bool nopartial)
{
	__wsum delta;

	if (!nopartial) {
		skb_remcsum_adjust_partial(skb, ptr, start, offset);
		return;
	}

	if (unlikely(skb->ip_summed != CHECKSUM_COMPLETE)) {
		__skb_checksum_complete(skb);
		skb_postpull_rcsum(skb, skb->data, ptr - (void *)skb->data);
	}

	delta = remcsum_adjust(ptr, skb->csum, start, offset);

	/* Adjust skb->csum since we changed the packet */
	skb->csum = csum_add(skb->csum, delta);
}

#endif  /* _LINUX_SKBUFF_API_EXTRA_H */
