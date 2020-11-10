/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Kerberos 5 crypto
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _CRYPTO_KRB5_H
#define _CRYPTO_KRB5_H

struct crypto_shash;
struct scatterlist;

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

#endif /* _CRYPTO_KRB5_H */
