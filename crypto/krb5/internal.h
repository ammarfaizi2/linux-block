/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Kerberos5 crypto internals
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/scatterlist.h>
#include <crypto/krb5.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>

/*
 * Profile used for key derivation and encryption.
 */
struct krb5_crypto_profile {
	 /* Pseudo-random function */
	int (*calc_PRF)(const struct krb5_enctype *krb5,
			const struct krb5_buffer *protocol_key,
			const struct krb5_buffer *octet_string,
			struct krb5_buffer *result,
			gfp_t gfp);

	/* Checksum key derivation */
	int (*calc_Kc)(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       const struct krb5_buffer *usage_constant,
		       struct krb5_buffer *Kc,
		       gfp_t gfp);

	/* Encryption key derivation */
	int (*calc_Ke)(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       const struct krb5_buffer *usage_constant,
		       struct krb5_buffer *Ke,
		       gfp_t gfp);

	 /* Integrity key derivation */
	int (*calc_Ki)(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       const struct krb5_buffer *usage_constant,
		       struct krb5_buffer *Ki,
		       gfp_t gfp);

	/* Encrypt data in-place, inserting confounder and checksum. */
	ssize_t (*encrypt)(const struct krb5_enctype *krb5,
			   struct krb5_enc_keys *keys,
			   struct scatterlist *sg, unsigned int nr_sg,
			   size_t sg_len,
			   size_t data_offset, size_t data_len,
			   bool preconfounded);

	/* Decrypt data in-place, removing confounder and checksum */
	int (*decrypt)(const struct krb5_enctype *krb5,
		       struct krb5_enc_keys *keys,
		       struct scatterlist *sg, unsigned int nr_sg,
		       size_t *_offset, size_t *_len,
		       int *_error_code);

	/* Generate a MIC on part of a packet, inserting the checksum */
	ssize_t (*get_mic)(const struct krb5_enctype *krb5,
			   struct crypto_shash *shash,
			   const struct krb5_buffer *metadata,
			   struct scatterlist *sg, unsigned int nr_sg,
			   size_t sg_len,
			   size_t data_offset, size_t data_len);

	/* Verify the MIC on a piece of data, removing the checksum */
	int (*verify_mic)(const struct krb5_enctype *krb5,
			  struct crypto_shash *shash,
			  const struct krb5_buffer *metadata,
			  struct scatterlist *sg, unsigned int nr_sg,
			  size_t *_offset, size_t *_len,
			  int *_error_code);
};

/*
 * Crypto size/alignment rounding convenience macros.
 */
#define crypto_roundup(X) ((unsigned int)round_up((X), CRYPTO_MINALIGN))

#define krb5_shash_size(TFM) \
	crypto_roundup(sizeof(struct shash_desc) + crypto_shash_descsize(TFM))
#define krb5_skcipher_size(TFM) \
	crypto_roundup(sizeof(struct skcipher_request) + crypto_skcipher_reqsize(TFM))
#define krb5_digest_size(TFM) \
	crypto_roundup(crypto_shash_digestsize(TFM))
#define krb5_sync_skcipher_size(TFM) \
	krb5_skcipher_size(&(TFM)->base)
#define krb5_sync_skcipher_ivsize(TFM) \
	crypto_roundup(crypto_sync_skcipher_ivsize(TFM))
#define round16(x) (((x) + 15) & ~15)

/*
 * main.c
 */
int crypto_shash_update_sg(struct shash_desc *desc, struct scatterlist *sg,
			   size_t offset, size_t len);

/*
 * rfc3961_simplified.c
 */
extern const struct krb5_crypto_profile rfc3961_simplified_profile;

ssize_t rfc3961_encrypt(const struct krb5_enctype *krb5,
			struct krb5_enc_keys *keys,
			struct scatterlist *sg, unsigned int nr_sg, size_t sg_len,
			size_t data_offset, size_t data_len,
			bool preconfounded);
int rfc3961_decrypt(const struct krb5_enctype *krb5,
		    struct krb5_enc_keys *keys,
		    struct scatterlist *sg, unsigned int nr_sg,
		    size_t *_offset, size_t *_len,
		    int *_error_code);
ssize_t rfc3961_get_mic(const struct krb5_enctype *krb5,
			struct crypto_shash *shash,
			const struct krb5_buffer *metadata,
			struct scatterlist *sg, unsigned int nr_sg, size_t sg_len,
			size_t data_offset, size_t data_len);
int rfc3961_verify_mic(const struct krb5_enctype *krb5,
		       struct crypto_shash *shash,
		       const struct krb5_buffer *metadata,
		       struct scatterlist *sg, unsigned int nr_sg,
		       size_t *_offset, size_t *_len,
		       int *_error_code);
