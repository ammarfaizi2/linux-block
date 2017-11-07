/* Copyright (c) 2018, Mellanox Technologies All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <net/tls.h>
#include <crypto/aead.h>
#include <crypto/scatterwalk.h>
#include <net/ip6_checksum.h>

static void chain_to_walk(struct scatterlist *sg, struct scatter_walk *walk)
{
	struct scatterlist *src = walk->sg;
	int diff = walk->offset - src->offset;

	sg_set_page(sg, sg_page(src),
		    src->length - diff, walk->offset);

	scatterwalk_crypto_chain(sg, sg_next(src), 0, 2);
}

static int tls_enc_record(struct aead_request *aead_req,
			  struct crypto_aead *aead, char *aad, char *iv,
			  __be64 rcd_sn, struct scatter_walk *in,
			  struct scatter_walk *out, int *in_len)
{
	unsigned char buf[TLS_HEADER_SIZE + TLS_CIPHER_AES_GCM_128_IV_SIZE];
	struct scatterlist sg_in[3];
	struct scatterlist sg_out[3];
	u16 len;
	int rc;

	len = min_t(int, *in_len, ARRAY_SIZE(buf));

	scatterwalk_copychunks(buf, in, len, 0);
	scatterwalk_copychunks(buf, out, len, 1);

	*in_len -= len;
	if (!*in_len)
		return 0;

	scatterwalk_pagedone(in, 0, 1);
	scatterwalk_pagedone(out, 1, 1);

	len = buf[4] | (buf[3] << 8);
	len -= TLS_CIPHER_AES_GCM_128_IV_SIZE;

	tls_make_aad(aad, len - TLS_CIPHER_AES_GCM_128_TAG_SIZE,
		     (char *)&rcd_sn, sizeof(rcd_sn), buf[0]);

	memcpy(iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, buf + TLS_HEADER_SIZE,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);

	sg_init_table(sg_in, ARRAY_SIZE(sg_in));
	sg_init_table(sg_out, ARRAY_SIZE(sg_out));
	sg_set_buf(sg_in, aad, TLS_AAD_SPACE_SIZE);
	sg_set_buf(sg_out, aad, TLS_AAD_SPACE_SIZE);
	chain_to_walk(sg_in + 1, in);
	chain_to_walk(sg_out + 1, out);

	*in_len -= len;
	if (*in_len < 0) {
		*in_len += TLS_CIPHER_AES_GCM_128_TAG_SIZE;
		if (*in_len < 0)
		/* the input buffer doesn't contain the entire record.
		 * trim len accordingly. The resulting authentication tag
		 * will contain garbage. but we don't care as we won't
		 * include any of it in the output skb
		 * Note that we assume the output buffer length
		 * is larger then input buffer length + tag size
		 */
			len += *in_len;

		*in_len = 0;
	}

	if (*in_len) {
		scatterwalk_copychunks(NULL, in, len, 2);
		scatterwalk_pagedone(in, 0, 1);
		scatterwalk_copychunks(NULL, out, len, 2);
		scatterwalk_pagedone(out, 1, 1);
	}

	len -= TLS_CIPHER_AES_GCM_128_TAG_SIZE;
	aead_request_set_crypt(aead_req, sg_in, sg_out, len, iv);

	rc = crypto_aead_encrypt(aead_req);

	return rc;
}

static void tls_init_aead_request(struct aead_request *aead_req,
				  struct crypto_aead *aead)
{
	aead_request_set_tfm(aead_req, aead);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
}

static struct aead_request *tls_alloc_aead_request(struct crypto_aead *aead,
						   gfp_t flags)
{
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(aead);
	struct aead_request *aead_req;

	aead_req = kzalloc(req_size, flags);
	if (!aead_req)
		return NULL;

	tls_init_aead_request(aead_req, aead);
	return aead_req;
}

static int tls_enc_records(struct aead_request *aead_req,
			   struct crypto_aead *aead, struct scatterlist *sg_in,
			   struct scatterlist *sg_out, char *aad, char *iv,
			   u64 rcd_sn, int len)
{
	struct scatter_walk out, in;
	int rc;

	scatterwalk_start(&in, sg_in);
	scatterwalk_start(&out, sg_out);

	do {
		rc = tls_enc_record(aead_req, aead, aad, iv,
				    cpu_to_be64(rcd_sn), &in, &out, &len);
		rcd_sn++;

	} while (rc == 0 && len);

	scatterwalk_done(&in, 0, 0);
	scatterwalk_done(&out, 1, 0);

	return rc;
}

/* Can't use icsk->icsk_af_ops->send_check here because the ip addresses
 * might have been changed by NAT.
 */
static inline void update_chksum(struct sk_buff *skb, int headln)
{
	struct tcphdr *th = tcp_hdr(skb);
	int datalen = skb->len - headln;
	const struct ipv6hdr *ipv6h;
	const struct iphdr *iph;

	/* We only changed the payload so if we are using partial we don't
	 * need to update anything.
	 */
	if (likely(skb->ip_summed == CHECKSUM_PARTIAL))
		return;

	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);

	if (skb->sk->sk_family == AF_INET6) {
		ipv6h = ipv6_hdr(skb);
		th->check = ~csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr,
					     datalen, IPPROTO_TCP, 0);
	} else {
		iph = ip_hdr(skb);
		th->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, datalen,
					       IPPROTO_TCP, 0);
	}
}

static void complete_skb(struct sk_buff *nskb, struct sk_buff *skb, int headln)
{
	skb_copy_header(nskb, skb);

	skb_put(nskb, skb->len);
	memcpy(nskb->data, skb->data, headln);
	update_chksum(nskb, headln);

	nskb->destructor = skb->destructor;
	nskb->sk = skb->sk;
	skb->destructor = NULL;
	skb->sk = NULL;
	refcount_add(nskb->truesize - skb->truesize,
		     &nskb->sk->sk_wmem_alloc);
}

/* This function may be called after the user socket is already
 * closed so make sure we don't use anything freed during
 * tls_sk_proto_close here
 */
static struct sk_buff *tls_sw_fallback(struct sock *sk, struct sk_buff *skb)
{
	int tcp_header_size = tcp_hdrlen(skb);
	int tcp_payload_offset = skb_transport_offset(skb) + tcp_header_size;
	int payload_len = skb->len - tcp_payload_offset;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_offload_context *ctx = tls_offload_ctx(tls_ctx);
	int remaining, buf_len, resync_sgs, rc, i = 0;
	void *buf, *dummy_buf, *iv, *aad;
	struct scatterlist *sg_in, sg_out[3];
	u32 tcp_seq = ntohl(tcp_hdr(skb)->seq);
	struct aead_request *aead_req;
	struct sk_buff *nskb = NULL;
	struct tls_record_info *record;
	unsigned long flags;
	s32 sync_size;
	u64 rcd_sn;

	/* worst case is:
	 * MAX_SKB_FRAGS in tls_record_info
	 * MAX_SKB_FRAGS + 1 in SKB head and frags.
	 */
	int sg_in_max_elements = 2 * MAX_SKB_FRAGS + 1;

	if (!payload_len)
		return skb;

	sg_in = kmalloc_array(sg_in_max_elements, sizeof(*sg_in), GFP_ATOMIC);
	if (!sg_in)
		goto free_orig;

	sg_init_table(sg_in, sg_in_max_elements);
	sg_init_table(sg_out, ARRAY_SIZE(sg_out));

	spin_lock_irqsave(&ctx->lock, flags);
	record = tls_get_record(ctx, tcp_seq, &rcd_sn);
	if (!record) {
		spin_unlock_irqrestore(&ctx->lock, flags);
		WARN(1, "Record not found for seq %u\n", tcp_seq);
		goto free_sg;
	}

	sync_size = tcp_seq - tls_record_start_seq(record);
	if (sync_size < 0) {
		int is_start_marker = tls_record_is_start_marker(record);

		spin_unlock_irqrestore(&ctx->lock, flags);
		if (!is_start_marker)
		/* This should only occur if the relevant record was
		 * already acked. In that case it should be ok
		 * to drop the packet and avoid retransmission.
		 *
		 * There is a corner case where the packet contains
		 * both an acked and a non-acked record.
		 * We currently don't handle that case and rely
		 * on TCP to retranmit a packet that doesn't contain
		 * already acked payload.
		 */
			goto free_orig;

		if (payload_len > -sync_size) {
			WARN(1, "Fallback of partially offloaded packets is not supported\n");
			goto free_sg;
		} else {
			return skb;
		}
	}

	remaining = sync_size;
	while (remaining > 0) {
		skb_frag_t *frag = &record->frags[i];

		__skb_frag_ref(frag);
		sg_set_page(sg_in + i, skb_frag_page(frag),
			    skb_frag_size(frag), frag->page_offset);

		remaining -= skb_frag_size(frag);

		if (remaining < 0)
			sg_in[i].length += remaining;

		i++;
	}
	spin_unlock_irqrestore(&ctx->lock, flags);
	resync_sgs = i;

	aead_req = tls_alloc_aead_request(ctx->aead_send, GFP_ATOMIC);
	if (!aead_req)
		goto put_sg;

	buf_len = TLS_CIPHER_AES_GCM_128_SALT_SIZE +
		  TLS_CIPHER_AES_GCM_128_IV_SIZE +
		  TLS_AAD_SPACE_SIZE +
		  sync_size +
		  tls_ctx->tag_size;
	buf = kmalloc(buf_len, GFP_ATOMIC);
	if (!buf)
		goto free_req;

	nskb = alloc_skb(skb_headroom(skb) + skb->len, GFP_ATOMIC);
	if (!nskb)
		goto free_buf;

	skb_reserve(nskb, skb_headroom(skb));

	iv = buf;

	memcpy(iv, tls_ctx->crypto_send_aes_gcm_128.salt,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	aad = buf + TLS_CIPHER_AES_GCM_128_SALT_SIZE +
	      TLS_CIPHER_AES_GCM_128_IV_SIZE;
	dummy_buf = aad + TLS_AAD_SPACE_SIZE;

	sg_set_buf(&sg_out[0], dummy_buf, sync_size);
	sg_set_buf(&sg_out[1], nskb->data + tcp_payload_offset,
		   payload_len);
	/* Add room for authentication tag produced by crypto */
	dummy_buf += sync_size;
	sg_set_buf(&sg_out[2], dummy_buf, tls_ctx->tag_size);
	rc = skb_to_sgvec(skb, &sg_in[i], tcp_payload_offset,
			  payload_len);
	if (rc < 0)
		goto free_nskb;

	rc = tls_enc_records(aead_req, ctx->aead_send, sg_in, sg_out, aad, iv,
			     rcd_sn, sync_size + payload_len);
	if (rc < 0)
		goto free_nskb;

	complete_skb(nskb, skb, tcp_payload_offset);

	/* validate_xmit_skb_list assumes that if the skb wasn't segmented
	 * nskb->prev will point to the skb itself
	 */
	nskb->prev = nskb;
free_buf:
	kfree(buf);
free_req:
	kfree(aead_req);
put_sg:
	for (i = 0; i < resync_sgs; i++)
		put_page(sg_page(&sg_in[i]));
free_sg:
	kfree(sg_in);
free_orig:
	kfree_skb(skb);
	return nskb;

free_nskb:
	kfree_skb(nskb);
	nskb = NULL;
	goto free_buf;
}

struct sk_buff *tls_validate_xmit_skb(struct sock *sk,
				      struct net_device *dev,
				      struct sk_buff *skb)
{
	if (dev == tls_get_ctx(sk)->netdev)
		return skb;

	return tls_sw_fallback(sk, skb);
}

int tls_sw_fallback_init(struct sock *sk,
			 struct tls_offload_context *offload_ctx,
			 struct tls_crypto_info *crypto_info)
{
	const u8 *key;
	int rc;

	offload_ctx->aead_send =
	    crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(offload_ctx->aead_send)) {
		rc = PTR_ERR(offload_ctx->aead_send);
		pr_err_ratelimited("crypto_alloc_aead failed rc=%d\n", rc);
		offload_ctx->aead_send = NULL;
		goto err_out;
	}

	key = ((struct tls12_crypto_info_aes_gcm_128 *)crypto_info)->key;

	rc = crypto_aead_setkey(offload_ctx->aead_send, key,
				TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (rc)
		goto free_aead;

	rc = crypto_aead_setauthsize(offload_ctx->aead_send,
				     TLS_CIPHER_AES_GCM_128_TAG_SIZE);
	if (rc)
		goto free_aead;

	return 0;
free_aead:
	crypto_free_aead(offload_ctx->aead_send);
err_out:
	return rc;
}
