/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Common bits for GSSAPI-based RxRPC security.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <crypto/krb5.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>

/*
 * Per-key number context.  This is replaced when the connection is rekeyed.
 */
struct rxgk_context {
	refcount_t		usage;
	unsigned int		key_number;	/* Rekeying number (goes in the rx header) */
	unsigned long		flags;
#define RXGK_TK_NEEDS_REKEY	0		/* Set if this needs rekeying */
	unsigned long		expiry;		/* Expiration time of this key */
	long long		bytes_remaining; /* Remaining Tx lifetime of this key */
	const struct krb5_enctype *krb5;	/* RxGK encryption type */
	const struct rxgk_key	*key;

	/* We need up to 7 keys derived from the transport key, but we don't
	 * actually need the transport key.  Each key is derived by
	 * DK(TK,constant).
	 */
	struct krb5_enc_keys	tx_enc;		/* Transmission key */
	struct krb5_enc_keys	rx_enc;		/* Reception key */
	struct crypto_shash	*tx_Kc;		/* Transmission checksum key */
	struct crypto_shash	*rx_Kc;		/* Reception checksum key */
	struct krb5_enc_keys	resp_enc;	/* Response packet enc key */
};

#define xdr_round_up(x) (round_up((x), sizeof(__be32)))

/*
 * rxgk_app.c
 */
int rxgk_yfs_decode_ticket(struct rxrpc_connection *, struct sk_buff *,
			   unsigned int, unsigned int, struct key **);
int rxgk_extract_token(struct rxrpc_connection *, struct sk_buff *,
		       unsigned int, unsigned int, struct key **);

/*
 * rxgk_kdf.c
 */
void rxgk_put(struct rxgk_context *gk);
struct rxgk_context *rxgk_generate_transport_key(struct rxrpc_connection *conn,
						 const struct rxgk_key *key,
						 unsigned int key_number,
						 gfp_t gfp);
int rxgk_set_up_token_cipher(const struct krb5_buffer *server_key,
			     struct krb5_enc_keys *token_key,
			     unsigned int enctype,
			     const struct krb5_enctype **_krb5,
			     gfp_t gfp);

/*
 * Apply encryption and checksumming functions to part of a transmission
 * buffer.
 */
static inline
int rxgk_encrypt_txb(const struct krb5_enctype *krb5,
		     struct krb5_enc_keys *keys,
		     struct rxrpc_txbuf *txb,
		     u16 secure_offset, u16 secure_maxlen,
		     u16 data_offset, u16 data_len,
		     bool preconfounded)
{
	struct scatterlist sg[1];

	sg_init_table(sg, 1);
	sg_set_buf(&sg[0], txb->data + secure_offset, secure_maxlen);

	data_offset -= secure_offset;
	return crypto_krb5_encrypt(krb5, keys, sg, 1, secure_maxlen,
				   data_offset, data_len, preconfounded);
}

/*
 * Apply decryption and checksumming functions to part of an skbuff.  The
 * offset and length are updated to reflect the actual content of the encrypted
 * region.
 */
static inline
int rxgk_decrypt_skb(const struct krb5_enctype *krb5,
		     struct krb5_enc_keys *keys,
		     struct sk_buff *skb,
		     unsigned int *_offset, unsigned int *_len,
		     int *_error_code)
{
	struct scatterlist sg[16];
	size_t offset = 0, len = *_len;
	int nr_sg, ret;

	sg_init_table(sg, ARRAY_SIZE(sg));
	nr_sg = skb_to_sgvec(skb, sg, *_offset, len);
	if (unlikely(nr_sg < 0))
		return nr_sg;

	ret = crypto_krb5_decrypt(krb5, keys, sg, nr_sg,
				  &offset, &len, _error_code);

	*_offset += offset;
	*_len = len;
	return ret;
}

/*
 * Generate a checksum over some metadata and part of a transmission buffer and
 * insert the MIC into the buffer immediately prior to the data.
 */
static inline
int rxgk_get_mic_txb(const struct krb5_enctype *krb5,
		     struct crypto_shash *shash,
		     const struct krb5_buffer *metadata,
		     struct rxrpc_txbuf *txb,
		     u16 secure_offset, u16 secure_maxlen,
		     u16 data_offset, u16 data_len)
{
	struct scatterlist sg[1];

	sg_init_table(sg, ARRAY_SIZE(sg));
	sg_set_buf(&sg[0], txb->data + secure_offset, secure_maxlen);

	data_offset -= secure_offset;
	return crypto_krb5_get_mic(krb5, shash, metadata, sg, 1, secure_maxlen,
				   data_offset, data_len);
}

/*
 * Check the MIC on a region of an skbuff.  The offset and length are updated
 * to reflect the actual content of the secure region.
 */
static inline
int rxgk_verify_mic_skb(const struct krb5_enctype *krb5,
			struct crypto_shash *shash,
			const struct krb5_buffer *metadata,
			struct sk_buff *skb,
			unsigned int *_offset, unsigned int *_len,
			u32 *_error_code)
{
	struct scatterlist sg[16];
	size_t offset = 0, len = *_len;
	int nr_sg, ret;

	sg_init_table(sg, ARRAY_SIZE(sg));
	nr_sg = skb_to_sgvec(skb, sg, *_offset, len);
	if (unlikely(nr_sg < 0))
		return nr_sg;

	ret = crypto_krb5_verify_mic(krb5, shash, metadata, sg, nr_sg,
				     &offset, &len, _error_code);

	*_offset += offset;
	*_len = len;
	return ret;
}

/*
 * Find the size and offset of the data in an integrity message.
 */
static inline
size_t rxgk_where_is_the_data(const struct krb5_enctype *krb5,
			      size_t *_offset, size_t len)
{
	return crypto_krb5_where_is_the_data(krb5, _offset, len);
}
