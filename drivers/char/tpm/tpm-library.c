/* TPM call wrapper library.
 *
 * Copyright (C) 2010 IBM Corporation
 *
 * Author:
 * David Safford <safford@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#define pr_fmt(fmt) "TPMLIB: "fmt
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/tpm.h>
#include <linux/tpm_command.h>

#include "tpm-library.h"

static const char tpm_hmac_alg[] = "hmac(sha1)";
static const char tpm_hash_alg[] = "sha1";

struct tpm_sdesc {
	struct shash_desc shash;
	char ctx[];
};

static DEFINE_MUTEX(tpm_library_init_mutex);
static atomic_t tpm_library_usage;
static struct crypto_shash *tpm_hashalg;
static struct crypto_shash *tpm_hmacalg;

static int tpm_gen_odd_nonce(struct tpm_chip *chip,
			     struct tpm_odd_nonce *ononce)
{
	int ret;

	ret = tpm_get_random(chip, ononce->data, TPM_NONCE_SIZE);
	if (ret == TPM_NONCE_SIZE)
		ret = 0;
	else
		pr_info("tpm_get_random failed (%d)\n", ret);
	return ret;
}

static struct tpm_sdesc *tpm_init_sdesc(struct crypto_shash *alg)
{
	struct tpm_sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	sdesc->shash.flags = 0x0;
	return sdesc;
}

static int TSS_sha1(const unsigned char *data, unsigned int datalen,
		    unsigned char *digest)
{
	struct tpm_sdesc *sdesc;
	int ret;

	sdesc = tpm_init_sdesc(tpm_hashalg);
	if (IS_ERR(sdesc)) {
		pr_info("Can't alloc %s\n", tpm_hash_alg);
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

/**
 * TSS_rawhmac - Generate a HMAC(SHA1) from raw data
 * @digest: Result buffer - must be SHA1_DIGEST_SIZE in size
 * @key: The key to use in the HMAC generation
 * @keylen: The size of @key
 * @...: Pairs of size and pointer of data elements to load into hmac
 * @0,0: Terminator
 */
static int TSS_rawhmac(unsigned char *digest,
		       const unsigned char *key, unsigned keylen,
		       ...)
{
	struct tpm_sdesc *sdesc;
	va_list argp;
	unsigned int dlen;
	unsigned char *data;
	int ret;

	sdesc = tpm_init_sdesc(tpm_hmacalg);
	if (IS_ERR(sdesc)) {
		pr_info("Can't alloc %s\n", tpm_hmac_alg);
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_setkey(tpm_hmacalg, key, keylen);
	if (ret < 0)
		goto out;
	ret = crypto_shash_init(&sdesc->shash);
	if (ret < 0)
		goto out;

	va_start(argp, keylen);
	for (;;) {
		dlen = va_arg(argp, unsigned int);
		if (dlen == 0)
			break;
		data = va_arg(argp, unsigned char *);
		if (data == NULL) {
			ret = -EINVAL;
			break;
		}
		ret = crypto_shash_update(&sdesc->shash, data, dlen);
		if (ret < 0)
			break;
	}
	va_end(argp);
	if (!ret)
		ret = crypto_shash_final(&sdesc->shash, digest);
out:
	kfree(sdesc);
	return ret;
}

/**
 * TSS_authhmac - Calculate authorisation info to send to TPM
 * @digest: Result buffer - must be SHA1_DIGEST_SIZE in size
 * @key: The key to use in the HMAC generation
 * @keylen: The size of @key
 * @enonce: Even nonce
 * @ononce: Odd nonce
 * @cont: Continuation flag
 * @...: Pairs of size and pointer of data elements to load into hash
 * @0,0: Terminator
 *
 * calculate authorization info fields to send to TPM
 */
static int TSS_authhmac(unsigned char *digest,
			const unsigned char *key, unsigned keylen,
			const struct tpm_even_nonce *enonce,
			const struct tpm_odd_nonce *ononce,
			unsigned char cont,
			...)
{
	unsigned char paramdigest[SHA1_DIGEST_SIZE];
	struct tpm_sdesc *sdesc;
	unsigned int dlen;
	unsigned char *data;
	int ret;
	va_list argp;

	sdesc = tpm_init_sdesc(tpm_hashalg);
	if (IS_ERR(sdesc)) {
		pr_info("Can't alloc %s\n", tpm_hash_alg);
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_init(&sdesc->shash);
	if (ret < 0)
		goto out;
	va_start(argp, cont);
	for (;;) {
		dlen = va_arg(argp, unsigned int);
		if (dlen == 0)
			break;
		data = va_arg(argp, unsigned char *);
		if (!data) {
			ret = -EINVAL;
			break;
		}
		ret = crypto_shash_update(&sdesc->shash, data, dlen);
		if (ret < 0)
			break;
	}
	va_end(argp);
	if (!ret)
		ret = crypto_shash_final(&sdesc->shash, paramdigest);
	if (!ret)
		ret = TSS_rawhmac(digest, key, keylen,
				  SHA1_DIGEST_SIZE, paramdigest,
				  TPM_NONCE_SIZE, enonce->data,
				  TPM_NONCE_SIZE, ononce->data,
				  1, &cont,
				  0, 0);
out:
	kfree(sdesc);
	return ret;
}

/*
 * verify the AUTH1_COMMAND (Seal) result from TPM
 */
static int TSS_checkhmac1(unsigned char *buffer,
			  __be32 ordinal,
			  const struct tpm_odd_nonce *ononce,
			  const unsigned char *key, unsigned keylen,
			  ...)
{
	uint32_t bufsize;
	uint16_t tag;
	__be32 result;
	struct tpm_even_nonce *enonce;
	unsigned char *continueflag;
	unsigned char *authdata;
	unsigned char testhmac[SHA1_DIGEST_SIZE];
	unsigned char paramdigest[SHA1_DIGEST_SIZE];
	struct tpm_sdesc *sdesc;
	unsigned int dlen;
	unsigned int dpos;
	va_list argp;
	int ret;

	bufsize = LOAD32(buffer, TPM_SIZE_OFFSET);
	tag = LOAD16(buffer, 0);
	result = LOAD32BE(buffer, TPM_RETURN_OFFSET);
	if (tag == TPM_TAG_RSP_COMMAND)
		return 0;
	if (tag != TPM_TAG_RSP_AUTH1_COMMAND)
		return -EINVAL;
	authdata = buffer + bufsize - SHA1_DIGEST_SIZE;
	continueflag = authdata - 1;
	enonce = (void *)continueflag - TPM_NONCE_SIZE;

	sdesc = tpm_init_sdesc(tpm_hashalg);
	if (IS_ERR(sdesc)) {
		pr_info("Can't alloc %s\n", tpm_hash_alg);
		return PTR_ERR(sdesc);
	}
	ret = crypto_shash_init(&sdesc->shash);
	if (ret < 0)
		goto out;
	ret = crypto_shash_update(&sdesc->shash, (const u8 *)&result,
				  sizeof result);
	if (ret < 0)
		goto out;
	ret = crypto_shash_update(&sdesc->shash, (const u8 *)&ordinal,
				  sizeof(ordinal));
	if (ret < 0)
		goto out;
	va_start(argp, keylen);
	for (;;) {
		dlen = va_arg(argp, unsigned int);
		if (dlen == 0)
			break;
		dpos = va_arg(argp, unsigned int);
		ret = crypto_shash_update(&sdesc->shash, buffer + dpos, dlen);
		if (ret < 0)
			break;
	}
	va_end(argp);
	if (!ret)
		ret = crypto_shash_final(&sdesc->shash, paramdigest);
	if (ret < 0)
		goto out;

	ret = TSS_rawhmac(testhmac, key, keylen,
			  SHA1_DIGEST_SIZE, paramdigest,
			  TPM_NONCE_SIZE, enonce->data,
			  TPM_NONCE_SIZE, ononce->data,
			  1, continueflag,
			  0, 0);
	if (ret < 0)
		goto out;

	if (memcmp(testhmac, authdata, SHA1_DIGEST_SIZE))
		ret = -EINVAL;
out:
	kfree(sdesc);
	return ret;
}

/*
 * verify the AUTH2_COMMAND (unseal) result from TPM
 */
static int TSS_checkhmac2(const unsigned char *buffer,
			  __be32 ordinal,
			  const struct tpm_odd_nonce *ononce,
			  const unsigned char *key1, unsigned keylen1,
			  const unsigned char *key2, unsigned keylen2,
			  ...)
{
	uint32_t bufsize;
	uint16_t tag;
	__be32 result;
	const struct tpm_even_nonce *enonce1;
	const unsigned char *continueflag1;
	const unsigned char *authdata1;
	const struct tpm_even_nonce *enonce2;
	const unsigned char *continueflag2;
	const unsigned char *authdata2;
	unsigned char testhmac1[SHA1_DIGEST_SIZE];
	unsigned char testhmac2[SHA1_DIGEST_SIZE];
	unsigned char paramdigest[SHA1_DIGEST_SIZE];
	struct tpm_sdesc *sdesc;
	unsigned int dlen;
	unsigned int dpos;
	va_list argp;
	int ret;

	bufsize = LOAD32(buffer, TPM_SIZE_OFFSET);
	tag = LOAD16(buffer, 0);
	result = LOAD32BE(buffer, TPM_RETURN_OFFSET);

	if (tag == TPM_TAG_RSP_COMMAND)
		return 0;
	if (tag != TPM_TAG_RSP_AUTH2_COMMAND)
		return -EINVAL;
	authdata1 = buffer + bufsize - (SHA1_DIGEST_SIZE + 1
			+ SHA1_DIGEST_SIZE + SHA1_DIGEST_SIZE);
	authdata2 = buffer + bufsize - (SHA1_DIGEST_SIZE);
	continueflag1 = authdata1 - 1;
	continueflag2 = authdata2 - 1;
	enonce1 = (const void *)continueflag1 - TPM_NONCE_SIZE;
	enonce2 = (const void *)continueflag2 - TPM_NONCE_SIZE;

	sdesc = tpm_init_sdesc(tpm_hashalg);
	if (IS_ERR(sdesc)) {
		pr_info("Can't alloc %s\n", tpm_hash_alg);
		return PTR_ERR(sdesc);
	}
	ret = crypto_shash_init(&sdesc->shash);
	if (ret < 0)
		goto out;
	ret = crypto_shash_update(&sdesc->shash, (const u8 *)&result,
				  sizeof(result));
	if (ret < 0)
		goto out;
	ret = crypto_shash_update(&sdesc->shash, (const u8 *)&ordinal,
				  sizeof(ordinal));
	if (ret < 0)
		goto out;

	va_start(argp, keylen2);
	for (;;) {
		dlen = va_arg(argp, unsigned int);
		if (dlen == 0)
			break;
		dpos = va_arg(argp, unsigned int);
		ret = crypto_shash_update(&sdesc->shash, buffer + dpos, dlen);
		if (ret < 0)
			break;
	}
	va_end(argp);
	if (!ret)
		ret = crypto_shash_final(&sdesc->shash, paramdigest);
	if (ret < 0)
		goto out;

	ret = TSS_rawhmac(testhmac1, key1, keylen1,
			  SHA1_DIGEST_SIZE, paramdigest,
			  TPM_NONCE_SIZE, enonce1->data,
			  TPM_NONCE_SIZE, ononce->data,
			  1, continueflag1,
			  0, 0);
	if (ret < 0)
		goto out;
	if (memcmp(testhmac1, authdata1, SHA1_DIGEST_SIZE)) {
		ret = -EINVAL;
		goto out;
	}
	ret = TSS_rawhmac(testhmac2, key2, keylen2,
			  SHA1_DIGEST_SIZE, paramdigest,
			  TPM_NONCE_SIZE, enonce2->data,
			  TPM_NONCE_SIZE, ononce->data,
			  1, continueflag2,
			  0, 0);
	if (ret < 0)
		goto out;
	if (memcmp(testhmac2, authdata2, SHA1_DIGEST_SIZE))
		ret = -EINVAL;
out:
	kfree(sdesc);
	return ret;
}

/*
 * For key specific tpm requests, we will generate and send our
 * own TPM command packets using the drivers send function.
 */
static int tpm_send_dump(struct tpm_chip *chip,
			 unsigned char *cmd, size_t buflen, const char *desc)
{
	int rc;

	dump_tpm_buf(cmd);
	rc = tpm_send_command(chip, cmd, buflen, desc);
	dump_tpm_buf(cmd);
	if (rc > 0)
		/* Can't return positive return codes values to keyctl */
		rc = -EPERM;
	return rc;
}

/*
 * Create an object specific authorisation protocol (OSAP) session
 */
static int tpm_create_osap(struct tpm_chip *chip,
			   struct tpm_buf *tb, struct tpm_osapsess *s,
			   const unsigned char *keyauth,
			   enum tpm_entity_type keytype, uint32_t keyhandle)
{
	struct tpm_even_nonce enonce;
	struct tpm_odd_nonce ononce;
	int ret;

	ret = tpm_gen_odd_nonce(chip, &ononce);
	if (ret < 0)
		return ret;

	INIT_BUF(tb);
	store16(tb, TPM_TAG_RQU_COMMAND);
	store32(tb, TPM_OSAP_SIZE);
	store32(tb, TPM_ORD_OSAP);
	store16(tb, keytype);
	store32(tb, keyhandle);
	store_s(tb, ononce.data, TPM_NONCE_SIZE);

	ret = tpm_send_dump(chip, tb->data, MAX_BUF_SIZE,
			    "creating OSAP session");
	if (ret < 0)
		return ret;

	s->handle = LOAD32(tb->data, TPM_DATA_OFFSET);
	memcpy(s->enonce.data, &(tb->data[TPM_DATA_OFFSET + sizeof(uint32_t)]),
	       TPM_NONCE_SIZE);
	memcpy(enonce.data, &(tb->data[TPM_DATA_OFFSET + sizeof(uint32_t) +
				  TPM_NONCE_SIZE]), TPM_NONCE_SIZE);
	return TSS_rawhmac(s->secret, keyauth, SHA1_DIGEST_SIZE,
			   TPM_NONCE_SIZE, enonce.data,
			   TPM_NONCE_SIZE, ononce.data,
			   0, 0);
}

/*
 * Create an object independent authorisation protocol (oiap) session
 */
static int tpm_create_oiap(struct tpm_chip *chip, struct tpm_buf *tb,
			   uint32_t *handle, struct tpm_even_nonce *enonce)
{
	int ret;

	INIT_BUF(tb);
	store16(tb, TPM_TAG_RQU_COMMAND);
	store32(tb, TPM_OIAP_SIZE);
	store32(tb, TPM_ORD_OIAP);
	ret = tpm_send_dump(chip, tb->data, MAX_BUF_SIZE,
			    "creating OIAP session");
	if (ret < 0)
		return ret;

	*handle = LOAD32(tb->data, TPM_DATA_OFFSET);
	memcpy(enonce->data, &tb->data[TPM_DATA_OFFSET + sizeof(uint32_t)],
	       TPM_NONCE_SIZE);
	return 0;
}

struct tpm_digests {
	unsigned char encauth[SHA1_DIGEST_SIZE];
	unsigned char pubauth[SHA1_DIGEST_SIZE];
	unsigned char xorwork[SHA1_DIGEST_SIZE * 2];
	unsigned char xorhash[SHA1_DIGEST_SIZE];
	struct tpm_odd_nonce ononce;
};

/**
 * tpm_seal - Encrypt one key according to another plus PCR state
 * @chip: The chip to use
 * @tb: Large scratch buffer for I/O
 * @keytype: Type of entity attached to @keyhandle
 * @keyhandle: TPM-resident key used to encrypt
 * @keyauth: 'Password' to use the key.
 * @rawdata: Data to be encrypted
 * @rawlen: Length of @rawdata
 * @encbuffer: Buffer to hold the encrypted data (max SHA1_DIGEST_SIZE)
 * @_enclen: Where to place the size of the encrypted data
 * @encauth: 'Password' to use to encrypt authorisation key
 * @pcrinfo: Information on PCR register values to seal to
 * @pcrinfosize: size of @pcrinfo
 *
 * Have the TPM seal (encrypt) the data in the data buffer.  The encryption is
 * based on a key already resident in the TPM and may also include the state of
 * one or more Platform Configuration Registers (PCRs).
 *
 * AUTH1 is used for sealing key.
 */
int tpm_seal(struct tpm_chip *chip,
	     struct tpm_buf *tb, enum tpm_entity_type keytype,
	     uint32_t keyhandle, const unsigned char *keyauth,
	     const unsigned char *rawdata, uint32_t rawlen,
	     unsigned char *encbuffer, uint32_t *_enclen,
	     const unsigned char *encauth,
	     const unsigned char *pcrinfo, uint32_t pcrinfosize)
{
	struct tpm_osapsess sess;
	struct tpm_digests *td;
	unsigned char cont;
	__be32 ordinal_be;
	__be32 rawlen_be;
	__be32 pcrinfosize_be;
	int sealinfosize;
	int encdatasize;
	int storedsize;
	int ret;
	int i;

	/* alloc some work space for all the hashes */
	td = kmalloc(sizeof *td, GFP_KERNEL);
	if (!td)
		return -ENOMEM;

	/* get session for sealing key */
	ret = tpm_create_osap(chip, tb, &sess, keyauth, keytype, keyhandle);
	if (ret < 0)
		goto out;
	dump_sess(&sess);

	/* calculate encrypted authorization value */
	memcpy(td->xorwork, sess.secret, SHA1_DIGEST_SIZE);
	memcpy(td->xorwork + SHA1_DIGEST_SIZE, sess.enonce.data, SHA1_DIGEST_SIZE);
	ret = TSS_sha1(td->xorwork, SHA1_DIGEST_SIZE * 2, td->xorhash);
	if (ret < 0)
		goto out;

	ret = tpm_gen_odd_nonce(chip, &td->ononce);
	if (ret < 0)
		goto out;
	ordinal_be	= cpu_to_be32(TPM_ORD_SEAL);
	rawlen_be	= cpu_to_be32(rawlen);
	pcrinfosize_be	= cpu_to_be32(pcrinfosize);
	cont = 0;

	/* encrypt data authorization key */
	for (i = 0; i < SHA1_DIGEST_SIZE; ++i)
		td->encauth[i] = td->xorhash[i] ^ encauth[i];

	/* calculate authorization HMAC value */
	if (pcrinfosize == 0) {
		/* no pcr info specified */
		ret = TSS_authhmac(td->pubauth, sess.secret, SHA1_DIGEST_SIZE,
				   &sess.enonce, &td->ononce, cont,
				   sizeof(__be32), &ordinal_be,
				   SHA1_DIGEST_SIZE, td->encauth,
				   sizeof(__be32), &pcrinfosize_be,
				   sizeof(__be32), &rawlen_be,
				   rawlen, rawdata,
				   0, 0);
	} else {
		/* pcr info specified */
		ret = TSS_authhmac(td->pubauth, sess.secret, SHA1_DIGEST_SIZE,
				   &sess.enonce, &td->ononce, cont,
				   sizeof(__be32), &ordinal_be,
				   SHA1_DIGEST_SIZE, td->encauth,
				   sizeof(__be32), &pcrinfosize_be,
				   pcrinfosize, pcrinfo,
				   sizeof(__be32), &rawlen_be,
				   rawlen, rawdata,
				   0, 0);
	}
	if (ret < 0)
		goto out;

	/* build and send the TPM request packet */
	INIT_BUF(tb);
	store16(tb, TPM_TAG_RQU_AUTH1_COMMAND);
	store32(tb, TPM_SEAL_SIZE + pcrinfosize + rawlen);
	store32(tb, TPM_ORD_SEAL);
	store32(tb, keyhandle);
	store_s(tb, td->encauth, SHA1_DIGEST_SIZE);
	store32(tb, pcrinfosize);
	store_s(tb, pcrinfo, pcrinfosize);
	store32(tb, rawlen);
	store_s(tb, rawdata, rawlen);
	store32(tb, sess.handle);
	store_s(tb, td->ononce.data, TPM_NONCE_SIZE);
	store_8(tb, cont);
	store_s(tb, td->pubauth, SHA1_DIGEST_SIZE);

	ret = tpm_send_dump(chip, tb->data, MAX_BUF_SIZE,
			    "sealing data");
	if (ret < 0)
		goto out;

	/* calculate the size of the returned encrypted data */
	sealinfosize = LOAD32(tb->data, TPM_DATA_OFFSET + sizeof(uint32_t));
	encdatasize = LOAD32(tb->data, TPM_DATA_OFFSET + sizeof(uint32_t) +
			     sizeof(uint32_t) + sealinfosize);
	storedsize = sizeof(uint32_t) + sizeof(uint32_t) + sealinfosize +
	    sizeof(uint32_t) + encdatasize;

	/* check the HMAC in the response */
	ret = TSS_checkhmac1(tb->data, ordinal_be, &td->ononce,
			     sess.secret, SHA1_DIGEST_SIZE,
			     storedsize, TPM_DATA_OFFSET,
			     0, 0);

	/* copy the encrypted data to caller's buffer */
	if (!ret) {
		memcpy(encbuffer, tb->data + TPM_DATA_OFFSET, storedsize);
		*_enclen = storedsize;
	}
out:
	kfree(td);
	return ret;
}
EXPORT_SYMBOL_GPL(tpm_seal);

/**
 * tpm_unseal - Encrypt one key according to another plus PCR state
 * @chip: The chip to use
 * @tb: Large scratch buffer for I/O
 * @keyhandle: TPM-resident key used to decrypt
 * @keyauth: HMAC key
 * @encdata: Data to be decrypted
 * @enclen: Length of @encdata
 * @decauth: Data to use to decrypt the authorisation key
 * @rawbuffer: Buffer to hold the decrypted data (max SHA1_DIGEST_SIZE)
 * @_rawlen: Where to place the size of the decrypted data
 *
 * use the AUTH2_COMMAND form of unseal, to authorize both key and blob
 */
int tpm_unseal(struct tpm_chip *chip, struct tpm_buf *tb,
	       uint32_t keyhandle, const unsigned char *keyauth,
	       const unsigned char *encdata, int enclen,
	       const unsigned char *decauth,
	       unsigned char *rawbuffer, unsigned int *_rawlen)
{
	struct tpm_odd_nonce ononce;
	struct tpm_even_nonce enonce1;
	struct tpm_even_nonce enonce2;
	unsigned char authdata1[SHA1_DIGEST_SIZE];
	unsigned char authdata2[SHA1_DIGEST_SIZE];
	uint32_t authhandle1 = 0;
	uint32_t authhandle2 = 0;
	unsigned char cont = 0;
	__be32 ordinal;
	int ret;

	/* sessions for unsealing key and data */
	ret = tpm_create_oiap(chip, tb, &authhandle1, &enonce1);
	if (ret < 0) {
		pr_info("Failed to create OIAP 1 (%d)\n", ret);
		return ret;
	}
	ret = tpm_create_oiap(chip, tb, &authhandle2, &enonce2);
	if (ret < 0) {
		pr_info("Failed to create OIAP 2 (%d)\n", ret);
		return ret;
	}

	ordinal = cpu_to_be32(TPM_ORD_UNSEAL);
	ret = tpm_gen_odd_nonce(chip, &ononce);
	if (ret < 0)
		return ret;
	ret = TSS_authhmac(authdata1, keyauth, TPM_NONCE_SIZE,
			   &enonce1, &ononce, cont,
			   sizeof(__be32), &ordinal,
			   enclen, encdata,
			   0, 0);
	if (ret < 0)
		return ret;
	ret = TSS_authhmac(authdata2, decauth, TPM_NONCE_SIZE,
			   &enonce2, &ononce, cont,
			   sizeof(__be32), &ordinal,
			   enclen, encdata,
			   0, 0);
	if (ret < 0)
		return ret;

	/* build and send TPM request packet */
	INIT_BUF(tb);
	store16(tb, TPM_TAG_RQU_AUTH2_COMMAND);
	store32(tb, TPM_UNSEAL_SIZE + enclen);
	store32(tb, TPM_ORD_UNSEAL);
	store32(tb, keyhandle);
	store_s(tb, encdata, enclen);
	store32(tb, authhandle1);
	store_s(tb, ononce.data, TPM_NONCE_SIZE);
	store_8(tb, cont);
	store_s(tb, authdata1, SHA1_DIGEST_SIZE);
	store32(tb, authhandle2);
	store_s(tb, ononce.data, TPM_NONCE_SIZE);
	store_8(tb, cont);
	store_s(tb, authdata2, SHA1_DIGEST_SIZE);

	ret = tpm_send_dump(chip, tb->data, MAX_BUF_SIZE,
			    "unsealing data");
	if (ret < 0) {
		pr_info("authhmac failed (%d)\n", ret);
		return ret;
	}

	*_rawlen = LOAD32(tb->data, TPM_DATA_OFFSET);
	ret = TSS_checkhmac2(tb->data, ordinal, &ononce,
			     keyauth, SHA1_DIGEST_SIZE,
			     decauth, SHA1_DIGEST_SIZE,
			     sizeof(uint32_t), TPM_DATA_OFFSET,
			     *_rawlen, TPM_DATA_OFFSET + sizeof(uint32_t),
			     0, 0);
	if (ret < 0) {
		pr_info("TSS_checkhmac2 failed (%d)\n", ret);
		return ret;
	}
	memcpy(rawbuffer, tb->data + TPM_DATA_OFFSET + sizeof(uint32_t), *_rawlen);
	return 0;
}
EXPORT_SYMBOL_GPL(tpm_unseal);

/**
 * tpm_library_use - Tell the TPM library we want to make use of it
 *
 * Tell the TPM library that we want to make use of it, allowing it to
 * allocate the resources it needs.
 */
int tpm_library_use(void)
{
	struct crypto_shash *hashalg = NULL;
	struct crypto_shash *hmacalg = NULL;
	int ret;

	if (atomic_inc_not_zero(&tpm_library_usage))
		return 0;

	/* We don't want to hold a mutex whilst allocating a crypto
	 * object as it may have to call up to userspace.
	 */
	hmacalg = crypto_alloc_shash(tpm_hmac_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hmacalg)) {
		pr_info("Could not allocate crypto %s\n", tpm_hmac_alg);
		ret = PTR_ERR(hmacalg);
		goto hmacalg_fail;
	}

	hashalg = crypto_alloc_shash(tpm_hash_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hashalg)) {
		pr_info("Could not allocate crypto %s\n", tpm_hash_alg);
		ret = PTR_ERR(hashalg);
		goto hashalg_fail;
	}

	mutex_lock(&tpm_library_init_mutex);

	if (atomic_inc_return(&tpm_library_usage) == 1) {
		tpm_hmacalg = hmacalg;
		tpm_hashalg = hashalg;
	} else {
		crypto_free_shash(hashalg);
		crypto_free_shash(hmacalg);
	}

	mutex_unlock(&tpm_library_init_mutex);
	return 0;

hashalg_fail:
	crypto_free_shash(tpm_hmacalg);
hmacalg_fail:
	return ret;
}
EXPORT_SYMBOL_GPL(tpm_library_use);

/**
 * tpm_library_unuse - Tell the TPM library we've finished with it
 *
 * Tell the TPM library we've finished with it, allowing it to free the
 * resources it had allocated.
 */
void tpm_library_unuse(void)
{
	if (atomic_add_unless(&tpm_library_usage, -1, 1))
		return;

	mutex_lock(&tpm_library_init_mutex);

	if (atomic_dec_and_test(&tpm_library_usage)) {
		crypto_free_shash(tpm_hashalg);
		crypto_free_shash(tpm_hmacalg);
	}

	mutex_unlock(&tpm_library_init_mutex);
}
EXPORT_SYMBOL_GPL(tpm_library_unuse);
