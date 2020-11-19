// SPDX-License-Identifier: GPL-2.0-or-later
/* Kerberos 5 crypto library.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include "internal.h"

MODULE_DESCRIPTION("Kerberos 5 crypto");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

static const struct krb5_enctype *const krb5_supported_enctypes[] = {
};

/**
 * crypto_krb5_find_enctype - Find the handler for a Kerberos5 encryption type
 * @enctype: The standard Kerberos encryption type number
 *
 * Look up a Kerberos encryption type by number.  If successful, returns a
 * pointer to the type tables; returns NULL otherwise.
 */
const struct krb5_enctype *crypto_krb5_find_enctype(u32 enctype)
{
	const struct krb5_enctype *krb5;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(krb5_supported_enctypes); i++) {
		krb5 = krb5_supported_enctypes[i];
		if (krb5->etype == enctype)
			return krb5;
	}

	return NULL;
}
EXPORT_SYMBOL(crypto_krb5_find_enctype);

int crypto_shash_update_sg(struct shash_desc *desc, struct scatterlist *sg,
			   size_t offset, size_t len)
{
	do {
		int ret;

		if (offset < sg->length) {
			struct page *page = sg_page(sg);
			void *p = kmap_local_page(page);
			void *q = p + sg->offset + offset;
			size_t seg = min_t(size_t, len, sg->length - offset);

			ret = crypto_shash_update(desc, q, seg);
			kunmap_local(p);
			if (ret < 0)
				return ret;
			len -= seg;
			offset = 0;
		} else {
			offset -= sg->length;
		}
	} while (len > 0 && (sg = sg_next(sg)));
	return 0;
}

/**
 * crypto_krb5_how_much_buffer - Work out how much buffer is required for an amount of data
 * @krb5: The encoding to use.
 * @mode: The mode in which to operated (checksum/encrypt)
 * @pad: True if the data should be padded anyway
 * @data_size: How much data we want to allow for
 * @_offset: Where to place the offset into the buffer
 *
 * Calculate how much buffer space is required to wrap a given amount of data.
 * This allows for a confounder, padding and checksum as appropriate.  The
 * amount of buffer required is returned and the offset into the buffer at
 * which the data will start is placed in *_offset.
 */
size_t crypto_krb5_how_much_buffer(const struct krb5_enctype *krb5,
				   enum krb5_crypto_mode mode, bool pad,
				   size_t data_size, size_t *_offset)
{
	switch (mode) {
	case KRB5_CHECKSUM_MODE:
		*_offset = krb5->cksum_len;
		return krb5->cksum_len + data_size;

	case KRB5_ENCRYPT_MODE:
		data_size += krb5->conf_len;
		if (pad || krb5->pad)
			data_size = round_up(data_size, krb5->block_len);
		*_offset = krb5->conf_len;
		return krb5->cksum_len + data_size;

	default:
		WARN_ON(1);
		*_offset = 0;
		return 0;
	}
}
EXPORT_SYMBOL(crypto_krb5_how_much_buffer);

/**
 * crypto_krb5_how_much_data - Work out how much data can fit in an amount of buffer
 * @krb5: The encoding to use.
 * @mode: The mode in which to operated (checksum/encrypt)
 * @pad: True if the data should be padded anyway
 * @_buffer_size: How much buffer we want to allow for (may be reduced)
 * @_offset: Where to place the offset into the buffer
 *
 * Calculate how much data can be fitted into given amount of buffer.  This
 * allows for a confounder, padding and checksum as appropriate.  The amount of
 * data that will fit is returned, the amount of buffer required is shrunk to
 * allow for alignment and the offset into the buffer at which the data will
 * start is placed in *_offset.
 */
size_t crypto_krb5_how_much_data(const struct krb5_enctype *krb5,
				 enum krb5_crypto_mode mode, bool pad,
				 size_t *_buffer_size, size_t *_offset)
{
	size_t buffer_size = *_buffer_size, data_size, aligned_size;

	switch (mode) {
	case KRB5_CHECKSUM_MODE:
		if (WARN_ON(buffer_size < krb5->cksum_len + 1))
			goto bad;
		*_offset = krb5->cksum_len;
		return buffer_size - krb5->cksum_len;

	case KRB5_ENCRYPT_MODE:
		if (WARN_ON(buffer_size < krb5->conf_len + 1 + krb5->cksum_len))
			goto bad;
		data_size = buffer_size - krb5->cksum_len;
		if (pad || krb5->pad) {
			aligned_size = round_down(data_size, krb5->block_len);
			*_buffer_size -= data_size - aligned_size;
			data_size = aligned_size;
		}

		*_offset = krb5->conf_len;
		return data_size - krb5->conf_len;

	default:
		WARN_ON(1);
		goto bad;
	}

bad:
	*_offset = 0;
	return 0;
}
EXPORT_SYMBOL(crypto_krb5_how_much_data);

/**
 * crypto_krb5_encrypt - Apply Kerberos encryption and integrity.
 * @krb5: The encoding to use.
 * @keys: The encryption and integrity keys to use.
 * @sg: Scatterlist defining the crypto buffer.
 * @nr_sg: The number of elements in @sg.
 * @sg_len: The size of the buffer.
 * @data_offset: The offset of the data in the @sg buffer.
 * @data_len: The length of the data.
 * @preconfounded: True if the confounder is already inserted.
 *
 * Using the specified Kerberos encoding, insert a confounder and padding as
 * needed, encrypt this and the data in place and insert an integrity checksum
 * into the buffer.
 *
 * The buffer must include space for the confounder, the checksum and any
 * padding required.  The caller can preinsert the confounder into the buffer
 * (for testing, for example).
 *
 * The resulting secured blob may be less than the size of the buffer.
 *
 * Returns the size of the secure blob if successful, -ENOMEM on an allocation
 * failure, -EFAULT if there is insufficient space, -EMSGSIZE if the confounder
 * is too short or the data is misaligned.  Other errors may also be returned
 * from the crypto layer.
 */
ssize_t crypto_krb5_encrypt(const struct krb5_enctype *krb5,
			    struct krb5_enc_keys *keys,
			    struct scatterlist *sg, unsigned int nr_sg,
			    size_t sg_len,
			    size_t data_offset, size_t data_len,
			    bool preconfounded)
{
	if (WARN_ON(data_offset > sg_len ||
		    data_len > sg_len ||
		    data_offset > sg_len - data_len))
		return -EMSGSIZE;
	return krb5->profile->encrypt(krb5, keys, sg, nr_sg, sg_len,
				      data_offset, data_len, preconfounded);
}
EXPORT_SYMBOL(crypto_krb5_encrypt);

/**
 * crypto_krb5_decrypt - Validate and remove Kerberos encryption and integrity.
 * @krb5: The encoding to use.
 * @keys: The encryption and integrity keys to use.
 * @sg: Scatterlist defining the crypto buffer.
 * @nr_sg: The number of elements in @sg.
 * @_offset: Offset of the secure blob in the buffer; updated to data offset.
 * @_len: The length of the secure blob; updated to data length.
 * @_error_code: Set to a Kerberos error code for parsing/validation errors.
 *
 * Using the specified Kerberos encoding, check and remove the integrity
 * checksum and decrypt the secure region, stripping off the confounder.
 *
 * If successful, @_offset and @_len are updated to outline the region in which
 * the data plus the trailing padding are stored.  The caller is responsible
 * for working out how much padding there is and removing it.
 *
 * Returns the 0 if successful, -ENOMEM on an allocation failure; sets
 * *_error_code and returns -EPROTO if the data cannot be parsed or if the
 * integrity checksum doesn't match).  Other errors may also be returned from
 * the crypto layer.
 */
int crypto_krb5_decrypt(const struct krb5_enctype *krb5,
			struct krb5_enc_keys *keys,
			struct scatterlist *sg, unsigned int nr_sg,
			size_t *_offset, size_t *_len,
			int *_error_code)
{
	return krb5->profile->decrypt(krb5, keys, sg, nr_sg,
				      _offset, _len, _error_code);
}
EXPORT_SYMBOL(crypto_krb5_decrypt);

/**
 * crypto_krb5_get_mic - Apply Kerberos integrity checksum.
 * @krb5: The encoding to use.
 * @shash: The keyed hash to use.
 * @metadata: Metadata to add into the hash before adding the data.
 * @sg: Scatterlist defining the crypto buffer.
 * @nr_sg: The number of elements in @sg.
 * @sg_len: The size of the buffer.
 * @data_offset: The offset of the data in the @sg buffer.
 * @data_len: The length of the data.
 *
 * Using the specified Kerberos encoding, calculate and insert an integrity
 * checksum into the buffer.
 *
 * The buffer must include space for the checksum at the front.
 *
 * Returns the size of the secure blob if successful, -ENOMEM on an allocation
 * failure, -EFAULT if there is insufficient space, -EMSGSIZE if the gap for
 * the checksum is too short.  Other errors may also be returned from the
 * crypto layer.
 */
ssize_t crypto_krb5_get_mic(const struct krb5_enctype *krb5,
			    struct crypto_shash *shash,
			    const struct krb5_buffer *metadata,
			    struct scatterlist *sg, unsigned int nr_sg,
			    size_t sg_len,
			    size_t data_offset, size_t data_len)
{
	if (WARN_ON(data_offset > sg_len ||
		    data_len > sg_len ||
		    data_offset > sg_len - data_len))
		return -EMSGSIZE;
	return krb5->profile->get_mic(krb5, shash, metadata, sg, nr_sg, sg_len,
				      data_offset, data_len);
}
EXPORT_SYMBOL(crypto_krb5_get_mic);

/**
 * crypto_krb5_verify_mic - Validate and remove Kerberos integrity checksum.
 * @krb5: The encoding to use.
 * @shash: The keyed hash to use.
 * @metadata: Metadata to add into the hash before adding the data.
 * @sg: Scatterlist defining the crypto buffer.
 * @nr_sg: The number of elements in @sg.
 * @_offset: Offset of the secure blob in the buffer; updated to data offset.
 * @_len: The length of the secure blob; updated to data length.
 * @_error_code: Set to a Kerberos error code for parsing/validation errors.
 *
 * Using the specified Kerberos encoding, check and remove the integrity
 * checksum.
 *
 * If successful, @_offset and @_len are updated to outline the region in which
 * the data is stored.
 *
 * Returns the 0 if successful, -ENOMEM on an allocation failure; sets
 * *_error_code and returns -EPROTO if the data cannot be parsed or if the
 * integrity checksum doesn't match).  Other errors may also be returned from
 * the crypto layer.
 */
int crypto_krb5_verify_mic(const struct krb5_enctype *krb5,
			   struct crypto_shash *shash,
			   const struct krb5_buffer *metadata,
			   struct scatterlist *sg, unsigned int nr_sg,
			   size_t *_offset, size_t *_len,
			   int *_error_code)
{
	return krb5->profile->verify_mic(krb5, shash, metadata, sg, nr_sg,
					 _offset, _len, _error_code);
}
EXPORT_SYMBOL(crypto_krb5_verify_mic);
