/* SPDX-License-Identifier: GPL-2.0-or-later */
/* rxgk common bits
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

struct crypto_shash;
struct rxgk_crypto_scheme;
struct rxgk_enc_keys;

enum krb5_crypto_mode {
	KRB5_CHECKSUM_MODE,
	KRB5_ENCRYPT_MODE,
};

/*
 * Kerberos encoding type definition.
 */
struct rxgk_krb5_enctype {
	int		etype;		/* encryption (key) type */
	int		ctype;		/* checksum type */
	const char	*name;		/* "friendly" name */
	const char	*encrypt_name;	/* crypto encrypt name */
	const char	*cksum_name;	/* crypto checksum name */
	const char	*hash_name;	/* crypto hash name */
	u32		blocksize;	/* encryption blocksize */
	u32		conflen;	/* confounder length
						   (normally the same as
						   the blocksize) */
	u32		cksumlength;	/* checksum length */
	bool		keyed_cksum;	/* is it a keyed cksum? */
	bool		pad;		/* T if should pad */
	u32		keybytes;	/* raw key len, in bytes */
	u32		keylength;	/* final key len, in bytes */
	u32		hashbytes;	/* Size of hash in bytes */
	u32		prf_len;	/* PRF() result size in bytes */
	u16		Kc_len;		/* Length of Kc in bytes */
	u16		Ke_len;		/* Length of Ke in bytes */
	u16		Ki_len;		/* Length of Ki in bytes */

	const struct rxgk_crypto_scheme *scheme;

	int (*random_to_key)(const struct rxgk_krb5_enctype *gk5e,
			     const struct rxgk_buffer *in,
			     struct rxgk_buffer *out);	/* complete key generation */
};

/*
 * Scheme used for key derivation and encryption style.
 */
struct rxgk_crypto_scheme {
	 /* Pseudo-random function */
	int (*calc_PRF)(const struct rxgk_krb5_enctype *gk5e,
			const struct rxgk_buffer *protocol_key,
			const struct rxgk_buffer *octet_string,
			struct rxgk_buffer *result,
			gfp_t gfp);

	/* Checksum key derivation */
	int (*calc_Kc)(const struct rxgk_krb5_enctype *gk5e,
		       const struct rxgk_buffer *TK,
		       const struct rxgk_buffer *usage_constant,
		       struct rxgk_buffer *Kc,
		       gfp_t gfp);

	/* Encryption key derivation */
	int (*calc_Ke)(const struct rxgk_krb5_enctype *gk5e,
		       const struct rxgk_buffer *TK,
		       const struct rxgk_buffer *usage_constant,
		       struct rxgk_buffer *Ke,
		       gfp_t gfp);

	 /* Integrity key derivation */
	int (*calc_Ki)(const struct rxgk_krb5_enctype *gk5e,
		       const struct rxgk_buffer *TK,
		       const struct rxgk_buffer *usage_constant,
		       struct rxgk_buffer *Ki,
		       gfp_t gfp);

	/* Encrypt part of a packet. */
	int (*encrypt_skb)(const struct rxgk_krb5_enctype *gk5e,
			   struct rxgk_enc_keys *keys,
			   struct sk_buff *skb,
			   u16 data_offset, u16 data_len,
			   bool preconfounded);

	/* Decrypt part of a packet. */
	int (*decrypt_skb)(struct rxrpc_call *call,
			   const struct rxgk_krb5_enctype *gk5e,
			   struct rxgk_enc_keys *keys,
			   struct sk_buff *skb,
			   unsigned int *_offset, unsigned int *_len,
			   u32 *_abort_code);

	/* Generate a MIC on part of a packet */
	int (*get_mic_skb)(const struct rxgk_krb5_enctype *gk5e,
			   struct crypto_shash *shash,
			   const struct rxgk_buffer *metadata,
			   struct sk_buff *skb,
			   u16 data_offset, u16 data_len);

	/* Verify the MIC on part of a packet */
	int (*verify_mic_skb)(struct rxrpc_call *call,
			      const struct rxgk_krb5_enctype *gk5e,
			      struct crypto_shash *shash,
			      const struct rxgk_buffer *metadata,
			      struct sk_buff *skb,
			      unsigned int *_offset, unsigned int *_len,
			      u32 *_abort_code);
};

/*
 * Encryption key and checksum for RxGK encryption.  These always come
 * as a pair as per RFC3961 encrypt().
 */
struct rxgk_enc_keys {
	struct crypto_sync_skcipher	*Ke; /* Encryption key */
	struct crypto_shash		*Ki; /* Checksum key */
};

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
	const struct rxgk_krb5_enctype *gk5e;	/* RxGK encryption type */
	const struct rxgk_key	*key;

	/* We need up to 7 keys derived from the transport key, but we don't
	 * actually need the transport key.  Each key is derived by
	 * DK(TK,constant).
	 */
	struct rxgk_enc_keys	tx_enc;		/* Transmission key */
	struct rxgk_enc_keys	rx_enc;		/* Reception key */
	struct crypto_shash	*tx_Kc;		/* Transmission checksum key */
	struct crypto_shash	*rx_Kc;		/* Reception checksum key */
	struct rxgk_enc_keys	resp_enc;	/* Response packet enc key */
};

#define crypto_roundup(X) round_up((X), CRYPTO_MINALIGN)

#define rxgk_shash_size(TFM) \
	crypto_roundup(sizeof(struct shash_desc) + crypto_shash_descsize(TFM))
#define rxgk_skcipher_size(TFM) \
	crypto_roundup(sizeof(struct skcipher_request) + crypto_skcipher_reqsize(TFM))
#define rxgk_digest_size(TFM) \
	crypto_roundup(crypto_shash_digestsize(TFM))
#define rxgk_sync_skcipher_size(TFM) \
	rxgk_skcipher_size(&(TFM)->base)
#define rxgk_sync_skcipher_ivsize(TFM) \
	crypto_roundup(crypto_sync_skcipher_ivsize(TFM))

#define round16(x) (((x) + 15) & ~15)

#define xdr_round_up(x) (round_up((x), sizeof(__be32)))

/*
 * rxgk_app.c
 */
int rxgk_yfs_decode_ticket(struct sk_buff *, unsigned int, unsigned int,
			   u32 *, struct key **);
int rxgk_extract_token(struct rxrpc_connection *,
		       struct sk_buff *, unsigned int, unsigned int,
		       struct key **, u32 *, const char **);

/*
 * rxgk_kdf.c
 */
const struct rxgk_krb5_enctype *rxgk_find_enctype(u32);
void rxgk_free_enc_keys(struct rxgk_enc_keys *);
struct rxgk_context *rxgk_generate_transport_key(struct rxrpc_connection *,
						 const struct rxgk_key *, unsigned int, gfp_t);
int rxgk_set_up_token_cipher(const struct rxgk_buffer *, struct rxgk_enc_keys *,
			     unsigned int, const struct rxgk_krb5_enctype **,
			     gfp_t);
void rxgk_put(struct rxgk_context *);
int crypto_shash_update_sg(struct shash_desc *desc, struct scatterlist *sg);

/*
 * rxgk_rfc3961.c
 */
extern const struct rxgk_crypto_scheme rfc3961_crypto_scheme;

int rfc3961_encrypt_skb(const struct rxgk_krb5_enctype *, struct rxgk_enc_keys *,
			struct sk_buff *, u16, u16, bool);
int rfc3961_decrypt_skb(struct rxrpc_call *, const struct rxgk_krb5_enctype *,
			struct rxgk_enc_keys *, struct sk_buff *,
			unsigned int *, unsigned int *, u32 *);
int rfc3961_get_mic_skb(const struct rxgk_krb5_enctype *, struct crypto_shash *,
			const struct rxgk_buffer *, struct sk_buff *, u16, u16);
int rfc3961_verify_mic_skb(struct rxrpc_call *, const struct rxgk_krb5_enctype *,
			   struct crypto_shash *, const struct rxgk_buffer *,
			   struct sk_buff *, unsigned int *, unsigned int *, u32 *);
size_t rxgk_krb5_how_much_buffer(const struct rxgk_krb5_enctype *,
				 enum krb5_crypto_mode, bool, size_t, size_t *);
size_t rxgk_krb5_how_much_data(const struct rxgk_krb5_enctype *,
			       enum krb5_crypto_mode, bool, size_t *, size_t *);

/*
 * rxgk_rfc3962.c
 */
extern const struct rxgk_krb5_enctype rxgk_aes128_cts_hmac_sha1_96;
extern const struct rxgk_krb5_enctype rxgk_aes256_cts_hmac_sha1_96;
