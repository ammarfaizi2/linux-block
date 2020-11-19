/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Kerberos 5 crypto
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _CRYPTO_KRB5_H
#define _CRYPTO_KRB5_H

#include <linux/crypto.h>

struct crypto_shash;
struct scatterlist;

enum krb5_crypto_mode {
	KRB5_CHECKSUM_MODE,
	KRB5_ENCRYPT_MODE,
};

/* per Kerberos v5 protocol spec crypto types from the wire.
 * these get mapped to linux kernel crypto routines.
 */
#define KRB5_ENCTYPE_NULL			0x0000
#define KRB5_ENCTYPE_DES_CBC_CRC		0x0001	/* DES cbc mode with CRC-32 */
#define KRB5_ENCTYPE_DES_CBC_MD4		0x0002	/* DES cbc mode with RSA-MD4 */
#define KRB5_ENCTYPE_DES_CBC_MD5		0x0003	/* DES cbc mode with RSA-MD5 */
#define KRB5_ENCTYPE_DES_CBC_RAW		0x0004	/* DES cbc mode raw */
/* XXX deprecated? */
#define KRB5_ENCTYPE_DES3_CBC_SHA		0x0005	/* DES-3 cbc mode with NIST-SHA */
#define KRB5_ENCTYPE_DES3_CBC_RAW		0x0006	/* DES-3 cbc mode raw */
#define KRB5_ENCTYPE_DES_HMAC_SHA1		0x0008
#define KRB5_ENCTYPE_DES3_CBC_SHA1		0x0010
#define KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96	0x0011
#define KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96	0x0012
#define KRB5_ENCTYPE_ARCFOUR_HMAC		0x0017
#define KRB5_ENCTYPE_ARCFOUR_HMAC_EXP		0x0018
#define KRB5_ENCTYPE_UNKNOWN			0x01ff

#define KRB5_CKSUMTYPE_CRC32			0x0001
#define KRB5_CKSUMTYPE_RSA_MD4			0x0002
#define KRB5_CKSUMTYPE_RSA_MD4_DES		0x0003
#define KRB5_CKSUMTYPE_DESCBC			0x0004
#define KRB5_CKSUMTYPE_RSA_MD5			0x0007
#define KRB5_CKSUMTYPE_RSA_MD5_DES		0x0008
#define KRB5_CKSUMTYPE_NIST_SHA			0x0009
#define KRB5_CKSUMTYPE_HMAC_SHA1_DES3		0x000c
#define KRB5_CKSUMTYPE_HMAC_SHA1_96_AES128	0x000f
#define KRB5_CKSUMTYPE_HMAC_SHA1_96_AES256	0x0010
#define KRB5_CKSUMTYPE_HMAC_MD5_ARCFOUR		-138 /* Microsoft md5 hmac cksumtype */

/*
 * Constants used for key derivation
 */
/* from rfc3961 */
#define KEY_USAGE_SEED_CHECKSUM         (0x99)
#define KEY_USAGE_SEED_ENCRYPTION       (0xAA)
#define KEY_USAGE_SEED_INTEGRITY        (0x55)

struct krb5_buffer {
	unsigned int	len;
	void		*data;
};

/*
 * Encryption key and checksum for RxGK encryption.  These always come
 * as a pair as per RFC3961 encrypt().
 */
struct krb5_enc_keys {
	struct crypto_sync_skcipher	*Ke; /* Encryption key */
	struct crypto_shash		*Ki; /* Checksum key */
};

/*
 * Kerberos encoding type definition.
 */
struct krb5_enctype {
	int		etype;		/* Encryption (key) type */
	int		ctype;		/* Checksum type */
	const char	*name;		/* "Friendly" name */
	const char	*encrypt_name;	/* Crypto encrypt name */
	const char	*cksum_name;	/* Crypto checksum name */
	const char	*hash_name;	/* Crypto hash name */
	u16		block_len;	/* Length of encryption block */
	u16		conf_len;	/* Length of confounder (normally == block_len) */
	u16		cksum_len;	/* Length of checksum */
	u16		key_bytes;	/* Length of raw key, in bytes */
	u16		key_len;	/* Length of final key, in bytes */
	u16		hash_len;	/* Length of hash in bytes */
	u16		prf_len;	/* Length of PRF() result in bytes */
	u16		Kc_len;		/* Length of Kc in bytes */
	u16		Ke_len;		/* Length of Ke in bytes */
	u16		Ki_len;		/* Length of Ki in bytes */
	bool		keyed_cksum;	/* T if a keyed cksum */
	bool		pad;		/* T if should pad */

	const struct krb5_crypto_profile *profile;

	int (*random_to_key)(const struct krb5_enctype *krb5,
			     const struct krb5_buffer *in,
			     struct krb5_buffer *out);	/* complete key generation */
};

/*
 * main.c
 */
const struct krb5_enctype *crypto_krb5_find_enctype(u32 enctype);

size_t crypto_krb5_how_much_buffer(const struct krb5_enctype *krb5,
				   enum krb5_crypto_mode mode, bool pad,
				   size_t data_size, size_t *_offset);
size_t crypto_krb5_how_much_data(const struct krb5_enctype *krb5,
				 enum krb5_crypto_mode mode, bool pad,
				 size_t *_buffer_size, size_t *_offset);
ssize_t crypto_krb5_encrypt(const struct krb5_enctype *krb5,
			    struct krb5_enc_keys *keys,
			    struct scatterlist *sg, unsigned int nr_sg,
			    size_t sg_len,
			    size_t data_offset, size_t data_len,
			    bool preconfounded);
int crypto_krb5_decrypt(const struct krb5_enctype *krb5,
			struct krb5_enc_keys *keys,
			struct scatterlist *sg, unsigned int nr_sg,
			size_t *_offset, size_t *_len,
			int *_error_code);
ssize_t crypto_krb5_get_mic(const struct krb5_enctype *krb5,
			    struct crypto_shash *shash,
			    const struct krb5_buffer *metadata,
			    struct scatterlist *sg, unsigned int nr_sg,
			    size_t sg_len,
			    size_t data_offset, size_t data_len);
int crypto_krb5_verify_mic(const struct krb5_enctype *krb5,
			   struct crypto_shash *shash,
			   const struct krb5_buffer *metadata,
			   struct scatterlist *sg, unsigned int nr_sg,
			   size_t *_offset, size_t *_len,
			   int *_error_code);

/**
 * crypto_krb5_where_is_the_data - Find the data in an integrity message
 * @krb5: The encoding to use.
 * @_offset: Offset of the secure blob in the buffer; updated to data offset.
 * @len: The length of the secure blob.
 *
 * Update and return the offset and size of the data in an integrity message so
 * that this information can be used in the metadata buffer which will get
 * added to the digest by crypto_krb5_verify_mic().
 *
 * @_offset may be NULL if the offset isn't of interest.
 */
static inline size_t crypto_krb5_where_is_the_data(const struct krb5_enctype *krb5,
						   size_t *_offset, size_t len)
{
	return len - krb5->cksum_len;
}

/*
 * kdf.c
 */
void crypto_krb5_free_enc_keys(struct krb5_enc_keys *e);
int crypto_krb5_calc_PRFplus(const struct krb5_enctype *krb5,
			     const struct krb5_buffer *K,
			     unsigned int L,
			     const struct krb5_buffer *S,
			     struct krb5_buffer *result,
			     gfp_t gfp);
int crypto_krb5_get_Kc(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       u32 usage,
		       struct krb5_buffer *key,
		       struct crypto_shash **_shash,
		       gfp_t gfp);
int crypto_krb5_get_Ke(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       u32 usage,
		       struct krb5_buffer *key,
		       struct crypto_sync_skcipher **_ci,
		       gfp_t gfp);
int crypto_krb5_get_Ki(const struct krb5_enctype *krb5,
		       const struct krb5_buffer *TK,
		       u32 usage,
		       struct krb5_buffer *key,
		       struct crypto_shash **_shash,
		       gfp_t gfp);

#endif /* _CRYPTO_KRB5_H */
