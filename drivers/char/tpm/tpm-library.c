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
#define kenter(fmt, ...) pr_devel("==>%s("fmt")\n", __func__, ## __VA_ARGS__)
#define kleave(fmt, ...) pr_devel("<==%s()"fmt"\n", __func__, ## __VA_ARGS__)

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
 * @0,NULL: Terminator
 */
static int TSS_rawhmac(unsigned char *digest,
		       const unsigned char *key, unsigned keylen,
		       ...)
{
	struct tpm_sdesc *sdesc;
	va_list argp;
	unsigned int dlen;
	unsigned char *data;
	int ret, s;

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
	for (s = 1;; s++) {
		dlen = va_arg(argp, unsigned int);
		data = va_arg(argp, unsigned char *);
		if (!data)
			break;
		pr_devel("RAWHMAC %dH1: [%u] %*phN\n", s, dlen, dlen, data);
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
 * @0,NULL: Terminator
 *
 * Calculate authorization info fields to send to TPM
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
	int ret, s;
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
	for (s = 1;; s++) {
		dlen = va_arg(argp, unsigned int);
		data = va_arg(argp, unsigned char *);
		if (!data)
			break;
		pr_devel("AUTHHASH S%d: [%u] %*phN\n", s, dlen, dlen, data);
		ret = crypto_shash_update(&sdesc->shash, data, dlen);
		if (ret < 0)
			break;
	}
	va_end(argp);
	if (!ret)
		ret = crypto_shash_final(&sdesc->shash, paramdigest);
	if (!ret)
		ret = TSS_rawhmac(digest, key, keylen,
				  /* 1H1 */ SHA1_DIGEST_SIZE, paramdigest,
				  /* 2H1 */ TPM_NONCE_SIZE, enonce->data,
				  /* 3H1 */ TPM_NONCE_SIZE, ononce->data,
				  /* 4H1 */ 1, &cont,
				  0, NULL);
out:
	kfree(sdesc);
	return ret;
}

/**
 * TSS_checkhmac1 - Verify the result of an AUTH1_COMMAND (eg. Seal)
 * @digest: Reply buffer
 * @ordinal: The command ID, BE form
 * @ononce: Odd nonce
 * @key: The key to use in the HMAC generation
 * @keylen: The size of @key
 * @...: Pairs of size and pointer of data elements to load into hash
 * @0,NULL: Terminator
 */
static int TSS_checkhmac1(struct tpm_buf *tb,
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

	SET_BUF_OFFSET(tb, 0);
	tag = LOAD16(tb);
	bufsize = LOAD32(tb);
	result = LOAD32BE(tb);
	if (tag == TPM_TAG_RSP_COMMAND)
		return 0;
	if (tag != TPM_TAG_RSP_AUTH1_COMMAND)
		return -EINVAL;

	authdata = tb->data + bufsize - SHA1_DIGEST_SIZE;
	continueflag = authdata - 1;
	enonce = (void *)continueflag - TPM_NONCE_SIZE;

	/* Load the 1S, 2S, 3S, ... marked fields into a hash.  The digest
	 * value is then 1H1 loaded into the HMAC below.
	 */
	sdesc = tpm_init_sdesc(tpm_hashalg);
	if (IS_ERR(sdesc)) {
		pr_info("Can't alloc %s\n", tpm_hash_alg);
		return PTR_ERR(sdesc);
	}
	ret = crypto_shash_init(&sdesc->shash);
	if (ret < 0)
		goto out;
	ret = crypto_shash_update(&sdesc->shash, (const u8 *)&result,
				  sizeof(result)); /* 1S */
	if (ret < 0)
		goto out;
	ret = crypto_shash_update(&sdesc->shash, (const u8 *)&ordinal,
				  sizeof(ordinal)); /* 2S */
	if (ret < 0)
		goto out;
	va_start(argp, keylen);
	for (;;) {
		dlen = va_arg(argp, unsigned int);
		dpos = va_arg(argp, unsigned int);
		if (!dlen && !dpos)
			break;
		ret = crypto_shash_update(&sdesc->shash, tb->data + dpos, dlen);
		if (ret < 0)
			break;
	}
	va_end(argp);
	if (!ret)
		ret = crypto_shash_final(&sdesc->shash, paramdigest);
	if (ret < 0)
		goto out;

	/* Generate the HMAC digest */
	ret = TSS_rawhmac(testhmac, key, keylen,
			  /* 1H1 */ SHA1_DIGEST_SIZE, paramdigest,
			  /* 2H1 */ TPM_NONCE_SIZE, enonce->data,
			  /* 3H1 */ TPM_NONCE_SIZE, ononce->data,
			  /* 4H1 */ 1, continueflag,
			  0, NULL);
	if (ret < 0)
		goto out;

	if (memcmp(testhmac, authdata, SHA1_DIGEST_SIZE))
		ret = -EINVAL;
out:
	kfree(sdesc);
	return ret;
}

/**
 * TSS_checkhmac2 - Verify the result of an AUTH2_COMMAND (eg. Unseal)
 * @digest: Reply buffer
 * @ordinal: The command ID, BE form
 * @ononce: Odd nonce
 * @key1: The key to use in the authorisation session HMAC generation (nH1)
 * @keylen1: The size of @key1
 * @key2: The key to use in the data session HMAC generation (nH2)
 * @keylen2: The size of @key2
 * @...: Pairs of size and pointer of data elements to load into hash
 * @0,NULL: Terminator
 *
 * verify the AUTH2_COMMAND (unseal) result from TPM
 */
static int TSS_checkhmac2(struct tpm_buf *tb,
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

	bufsize = LOAD32(tb);
	tag = LOAD16(tb);
	result = LOAD32BE(tb);

	if (tag == TPM_TAG_RSP_COMMAND)
		return 0;
	if (tag != TPM_TAG_RSP_AUTH2_COMMAND)
		return -EINVAL;
	authdata1 = tb->data + bufsize - (SHA1_DIGEST_SIZE + 1
			+ SHA1_DIGEST_SIZE + SHA1_DIGEST_SIZE);
	authdata2 = tb->data + bufsize - (SHA1_DIGEST_SIZE);
	continueflag1 = authdata1 - 1;
	continueflag2 = authdata2 - 1;
	enonce1 = (const void *)continueflag1 - TPM_NONCE_SIZE;
	enonce2 = (const void *)continueflag2 - TPM_NONCE_SIZE;

	/* Load the 1S, 2S, 3S, ... marked fields into a hash.  The digest
	 * value is then 1H1 loaded into the HMAC below.
	 */
	sdesc = tpm_init_sdesc(tpm_hashalg);
	if (IS_ERR(sdesc)) {
		pr_info("Can't alloc %s\n", tpm_hash_alg);
		return PTR_ERR(sdesc);
	}
	ret = crypto_shash_init(&sdesc->shash);
	if (ret < 0)
		goto out;
	ret = crypto_shash_update(&sdesc->shash, (const u8 *)&result,
				  sizeof(result)); /* 1S */
	if (ret < 0)
		goto out;
	ret = crypto_shash_update(&sdesc->shash, (const u8 *)&ordinal,
				  sizeof(ordinal)); /* 2S */
	if (ret < 0)
		goto out;

	va_start(argp, keylen2);
	for (;;) {
		dlen = va_arg(argp, unsigned int);
		dpos = va_arg(argp, unsigned int);
		if (!dlen && !dpos)
			break;
		ret = crypto_shash_update(&sdesc->shash, tb->data + dpos, dlen);
		if (ret < 0)
			break;
	}
	va_end(argp);
	if (!ret)
		ret = crypto_shash_final(&sdesc->shash, paramdigest);
	if (ret < 0)
		goto out;

	ret = TSS_rawhmac(testhmac1, key1, keylen1,
			  /* 1H1 */ SHA1_DIGEST_SIZE, paramdigest,
			  /* 2H1 */ TPM_NONCE_SIZE, enonce1->data,
			  /* 3H1 */ TPM_NONCE_SIZE, ononce->data,
			  /* 4H1 */ 1, continueflag1,
			  0, NULL);
	if (ret < 0)
		goto out;
	if (memcmp(testhmac1, authdata1, SHA1_DIGEST_SIZE)) {
		ret = -EINVAL;
		goto out;
	}
	ret = TSS_rawhmac(testhmac2, key2, keylen2,
			  /* 1H2 */ SHA1_DIGEST_SIZE, paramdigest,
			  /* 2H2 */ TPM_NONCE_SIZE, enonce2->data,
			  /* 3H2 */ TPM_NONCE_SIZE, ononce->data,
			  /* 4H2 */ 1, continueflag2,
			  0, NULL);
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
static int tpm_send_dump(struct tpm_chip *chip, struct tpm_buf *cmd,
			 const char *desc)
{
	int rc;

	kenter(",{%u,%u},%s",
	       cmd->len, be32_to_cpu(*(__be32 *)(cmd->data + TPM_SIZE_OFFSET)), desc);

	dump_tpm_buf(cmd);
	rc = tpm_send_command(chip, cmd->data, MAX_BUF_SIZE, desc);
	dump_tpm_buf(cmd);
	if (rc > 0)
		/* Can't return positive return codes values to keyctl */
		rc = -EPERM;
	else
		SET_BUF_OFFSET(cmd, TPM_DATA_OFFSET);
	kleave(" = %d [%u]", rc, be32_to_cpu(*(__be32 *)(cmd->data + TPM_SIZE_OFFSET)));
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

	kenter("");

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

	ret = tpm_send_dump(chip, tb, "creating OSAP session");
	if (ret < 0)
		goto out;

	s->handle = LOAD32(tb);
	LOAD_S(tb, s->enonce.data, TPM_NONCE_SIZE);
	LOAD_S(tb, enonce.data, TPM_NONCE_SIZE);

	/* Calculate the encrypted shared secret */
	ret = TSS_rawhmac(s->secret, keyauth, SHA1_DIGEST_SIZE,
			  TPM_NONCE_SIZE, enonce.data,
			  TPM_NONCE_SIZE, ononce.data,
			  0, NULL);
out:
	kleave(" = %d [%08x]", ret, s->handle);
	return ret;
}

/*
 * Create an object independent authorisation protocol (oiap) session
 */
static int tpm_create_oiap(struct tpm_chip *chip, struct tpm_buf *tb,
			   uint32_t *handle, struct tpm_even_nonce *enonce)
{
	int ret;

	kenter("");

	INIT_BUF(tb);
	store16(tb, TPM_TAG_RQU_COMMAND);
	store32(tb, TPM_OIAP_SIZE);
	store32(tb, TPM_ORD_OIAP);
	ret = tpm_send_dump(chip, tb, "creating OIAP session");
	if (ret < 0)
		return ret;

	*handle = LOAD32(tb);
	LOAD_S(tb, enonce->data, TPM_NONCE_SIZE);
	kleave(" = 0 [%08x]", *handle);
	return 0;
}

struct tpm_digests {
	unsigned char encauth[SHA1_DIGEST_SIZE];
	unsigned char encauth2[SHA1_DIGEST_SIZE];
	unsigned char pubauth[SHA1_DIGEST_SIZE];
	unsigned char xorwork[SHA1_DIGEST_SIZE * 2];
	unsigned char xorhash[SHA1_DIGEST_SIZE];
	struct tpm_odd_nonce ononce;
};

/*
 * Calculate an XOR-based symmetric key that can be used to encrypt protected
 * data.  The key is left in td->xorhash.
 */
static int tpm_calc_symmetric_authkey(struct tpm_digests *td,
				      const u8 *secret,
				      const struct tpm_even_nonce *enonce)
{
	memcpy(td->xorwork, secret, SHA1_DIGEST_SIZE);
	memcpy(td->xorwork + SHA1_DIGEST_SIZE, enonce->data, SHA1_DIGEST_SIZE);
	return TSS_sha1(td->xorwork, SHA1_DIGEST_SIZE * 2, td->xorhash);
}

/*
 * Encrypt/decrypt data with a previously calculated XOR-based symmetric key.
 */
static void tpm_crypt_with_authkey(const struct tpm_digests *td,
				   const u8 *data, u8 *buffer)
{
	int i;
	for (i = 0; i < SHA1_DIGEST_SIZE; ++i)
		buffer[i] = td->xorhash[i] ^ data[i];
}

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
 * @pcrinfo: Information on PCR register values to seal to (must not be NULL)
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

	kenter("");

	/* alloc some work space for all the hashes */
	td = kmalloc(sizeof *td, GFP_KERNEL);
	if (!td)
		return -ENOMEM;

	/* get session for sealing key */
	ret = tpm_create_osap(chip, tb, &sess, keyauth, keytype, keyhandle);
	if (ret < 0)
		goto out;
	dump_sess(&sess);

	/* We need to pass a 'password' to the TPM with which it will encrypt
	 * the sealed data before returning it.  So that the password doesn't
	 * travel to the TPM in the clear, we generate a symmetric key from the
	 * negotiated and encrypted session data and encrypt the password with
	 * that.
	 */
	ret = tpm_calc_symmetric_authkey(td, sess.secret, &sess.enonce);
	if (ret < 0)
		goto out;
	tpm_crypt_with_authkey(td, encauth, td->encauth);

	/* Set up the parameters we will be sending */
	ret = tpm_gen_odd_nonce(chip, &td->ononce);
	if (ret < 0)
		goto out;
	ordinal_be	= cpu_to_be32(TPM_ORD_SEAL);
	rawlen_be	= cpu_to_be32(rawlen);
	pcrinfosize_be	= cpu_to_be32(pcrinfosize);
	cont = 0;

	/* calculate authorization HMAC value */
	BUG_ON(!pcrinfo);
	ret = TSS_authhmac(td->pubauth, sess.secret, SHA1_DIGEST_SIZE,
			   &sess.enonce, &td->ononce, cont,
			   /* 1S */ sizeof(__be32), &ordinal_be,
			   /* 2S */ SHA1_DIGEST_SIZE, td->encauth,
			   /* 3S */ sizeof(__be32), &pcrinfosize_be,
			   /* 4S */ pcrinfosize, pcrinfo,
			   /* 5S */ sizeof(__be32), &rawlen_be,
			   /* 6S */ rawlen, rawdata,
			   0, NULL);
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

	ret = tpm_send_dump(chip, tb, "sealing data");
	if (ret < 0)
		goto out;

	/* Look inside the TPM_STORED_DATA object to calculate the size of the
	 * returned encrypted data.
	 */
	SET_BUF_OFFSET(tb, TPM_DATA_OFFSET + sizeof(uint32_t));
	sealinfosize = LOAD32(tb);
	SET_BUF_OFFSET(tb, TPM_DATA_OFFSET + sizeof(uint32_t) * 2 + sealinfosize);
	storedsize = sizeof(uint32_t) * 2 + sealinfosize +
		sizeof(uint32_t) + encdatasize;

	/* check the HMAC in the response */
	ret = TSS_checkhmac1(tb, ordinal_be, &td->ononce,
			     sess.secret, SHA1_DIGEST_SIZE,
			     /* 3S */ storedsize, TPM_DATA_OFFSET,
			     0, NULL);

	/* copy the encrypted data to caller's buffer */
	if (!ret) {
		SET_BUF_OFFSET(tb, TPM_DATA_OFFSET);
		LOAD_S(tb, encbuffer, storedsize);
		*_enclen = storedsize;
	}
out:
	kfree(td);
	kleave(" = %d", ret);
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

	kenter("");

	/* sessions for unsealing key and data */
	ret = tpm_create_oiap(chip, tb, &authhandle1, &enonce1);
	if (ret < 0) {
		pr_info("Failed to create OIAP 1 (%d)\n", ret);
		goto out;
	}
	ret = tpm_create_oiap(chip, tb, &authhandle2, &enonce2);
	if (ret < 0) {
		pr_info("Failed to create OIAP 2 (%d)\n", ret);
		goto out;
	}

	ordinal = cpu_to_be32(TPM_ORD_UNSEAL);
	ret = tpm_gen_odd_nonce(chip, &ononce);
	if (ret < 0)
		goto out;
	ret = TSS_authhmac(authdata1, keyauth, TPM_NONCE_SIZE,
			   &enonce1, &ononce, cont,
			   /* 1S */ sizeof(__be32), &ordinal,
			   /* 2S */ enclen, encdata,
			   0, NULL);
	if (ret < 0)
		goto out;
	ret = TSS_authhmac(authdata2, decauth, TPM_NONCE_SIZE,
			   &enonce2, &ononce, cont,
			   /* 1S */ sizeof(__be32), &ordinal,
			   /* 2S */ enclen, encdata,
			   0, NULL);
	if (ret < 0)
		goto out;

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

	ret = tpm_send_dump(chip, tb, "unsealing data");
	if (ret < 0) {
		pr_info("authhmac failed (%d)\n", ret);
		goto out;
	}

	*_rawlen = LOAD32(tb);
	ret = TSS_checkhmac2(tb, ordinal, &ononce,
			     keyauth, SHA1_DIGEST_SIZE,
			     decauth, SHA1_DIGEST_SIZE,
			     /* 3S */ sizeof(uint32_t), TPM_DATA_OFFSET,
			     /* 4S */ *_rawlen, TPM_DATA_OFFSET + sizeof(uint32_t),
			     0, 0);
	if (ret < 0) {
		pr_info("TSS_checkhmac2 failed (%d)\n", ret);
		goto out;
	}
	LOAD_S(tb, rawbuffer, *_rawlen);
out:
	kleave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL_GPL(tpm_unseal);

enum tpm_key_usage {
	TPM_KEY_SIGNING			= 0x0010,
	TPM_KEY_STORAGE			= 0x0011,
	TPM_KEY_IDENTITY		= 0x0012,
	TPM_KEY_AUTHCHANGE		= 0x0013,
	TPM_KEY_BIND			= 0x0014,
	TPM_KEY_LEGACY			= 0x0015,
	TPM_KEY_MIGRATE			= 0x0016,
};

enum tpm_algorithm_id {
	TPM_ALG_RSA			= 0x00000001,
	TPM_ALG_SHA			= 0x00000004,
	TPM_ALG_HMAC			= 0x00000005,
	TPM_ALG_AES128			= 0x00000006,
	TPM_ALG_MGF1			= 0x00000007,
	TPM_ALG_AES192			= 0x00000008,
	TPM_ALG_AES256			= 0x00000009,
	TPM_ALG_XOR			= 0x0000000a,
};

enum tpm_enc_scheme {
	TPM_ES_NONE			= 0x0001,
	TPM_ES_RSAESPKCSv15		= 0x0002,
	TPM_ES_RSAESOAEP_SHA1_MGF1	= 0x0003,
	TPM_ES_SYM_CTR			= 0x0004,
	TPM_ES_SYM_OFB			= 0x0005,
};

enum tpm_sig_scheme {
	TPM_SS_NONE			= 0x0001,
	TPM_SS_RSAESPKCSv15_SHA1	= 0x0002,
	TPM_SS_RSAESPKCSv15_DER		= 0x0003,
	TPM_SS_RSAESPKCSv15_INFO	= 0x0004,
};

enum tpm_auth_data_usage {
	TPM_AUTH_NEVER			= 0x00,
	TPM_AUTH_ALWAYS			= 0x01,
	TPM_NO_READ_PUBKEY_AUTH		= 0x03,
};

#define TPM_KEY_REDIRECTION		0x00000001
#define TPM_KEY_MIGRATABLE		0x00000002
#define TPM_KEY_ISVOLATILE		0x00000004
#define TPM_KEY_PCRIGNOREDONREAD	0x00000008
#define TPM_KEY_MIGRATEAUTHORITY	0x00000010

struct tpm_key {
	struct tpm_struct_ver {
		u8	major, minor, rev_major, rev_minor;
	} ver;
	__be16		key_usage;		/* enum tpm_key_usage */
	__be32		key_flags;
	u8		auth_data_usage;	/* enum tpm_auth_data_usage */
	struct tpm_key_parms {
		__be32		algorithm_id;	/* enum tpm_algorithm_id */
		__be16		enc_scheme;	/* enum tpm_enc_scheme */
		__be16		sig_scheme;	/* enum tpm_sig_scheme */
		__be32		parm_size;
		struct tpm_rsa_key_parms {
			__be32		key_length;
			__be32		num_primes;
			__be32		exponent_size;
		} __packed rsa;
	} __packed parms;
	__be32		pcr_info_size;
	struct tpm_store_pubkey {
		__be32		key_length;
		u8		key_data[0];
	} __packed pub;
	__be32		enc_data_size;
	u8		enc_data[0];
} __packed;

/**
 * tpm_create_wrap_key - Generate a new key and return it encrypted
 * @chip: The chip to use
 * @tb: Large scratch buffer for I/O
 * @parent_type: Type of entity attached to @parent_handle
 * @parent_handle: TPM-resident key used to encrypt
 * @parent_auth: Parent authorisation HMAC key
 * @usage_auth: Encrypted usage authdata for the key
 * @migration_auth: Encrypted migration authdata for the key (or NULL)
 * @_wrapped_key: Pointer to where to return the wrapped key (kmalloc'd)
 *
 * Have the TPM generate a new key and return it encrypted.  The encryption is
 * based on a key already resident in the TPM and may also include the state of
 * one or more Platform Configuration Registers (PCRs).
 *
 * AUTH1 is used for sealing key.
 */
int tpm_create_wrap_key(struct tpm_chip *chip,
			enum tpm_entity_type parent_type,
			uint32_t parent_handle,
			const unsigned char *parent_auth,
			const unsigned char *usage_auth,
			const unsigned char *migration_auth,
			struct tpm_wrapped_key **_wrapped_key)
{
	struct tpm_wrapped_key *wrapped_key;
	struct tpm_osapsess sess;
	struct tpm_digests *td;
	struct tpm_buf *tb;
	struct tpm_key *result;
	unsigned char cont;
	__be32 ordinal_be;
	int key_size;
	int ret;

	struct tpm_key tpm_key = {
		.ver			= { 0x01, 0x01, 0x00, 0x00 },
		.key_usage		= cpu_to_be16(TPM_KEY_SIGNING),
		.key_flags		= cpu_to_be32(0),
		.auth_data_usage	= TPM_AUTH_ALWAYS,
		.parms.algorithm_id	= cpu_to_be32(TPM_ALG_RSA),
		.parms.enc_scheme	= cpu_to_be16(TPM_ES_RSAESPKCSv15),
		.parms.sig_scheme	= cpu_to_be16(TPM_SS_RSAESPKCSv15_SHA1),
		.parms.parm_size	= cpu_to_be32(sizeof(struct tpm_rsa_key_parms)),
		.parms.rsa.key_length	= cpu_to_be32(2048),
		.parms.rsa.num_primes	= cpu_to_be32(2),
		.parms.rsa.exponent_size = cpu_to_be32(0),
		.pcr_info_size		= cpu_to_be32(0),
		.pub.key_length		= cpu_to_be32(0),
		.enc_data_size		= cpu_to_be32(0),
	};

	kenter("");

	if (migration_auth)
		tpm_key.key_flags |= cpu_to_be32(TPM_KEY_MIGRATABLE);

	/* alloc some work space */
	tb = kmalloc(sizeof(*tb) + sizeof(*td), GFP_KERNEL);
	if (!tb)
		return -ENOMEM;
	td = (void *)tb + sizeof(*tb);

	/* Get the encryption session */
	ret = tpm_create_osap(chip, tb, &sess,
			      parent_auth, parent_type, parent_handle);
	if (ret < 0)
		goto out;
	dump_sess(&sess);

	/* We need to pass 'passwords' to the TPM with which it will encrypt
	 * the key before returning it.  So that the passwords don't travel to
	 * the TPM in the clear, we generate a symmetric key from the
	 * negotiated and encrypted session data and encrypt the passwords with
	 * that.
	 */
	ret = tpm_calc_symmetric_authkey(td, sess.secret, &sess.enonce);
	if (ret < 0)
		goto out;
	tpm_crypt_with_authkey(td, usage_auth, td->encauth);
	if (migration_auth)
		tpm_crypt_with_authkey(td, migration_auth, td->encauth2);
	else
		tpm_crypt_with_authkey(td, sess.enonce.data, td->encauth2);

	/* Set up the parameters we will be sending */
	ret = tpm_gen_odd_nonce(chip, &td->ononce);
	if (ret < 0)
		goto out;

	/* calculate authorization HMAC value */
	ordinal_be = cpu_to_be32(TPM_ORD_CREATEWRAPKEY);
	cont = 0;
	ret = TSS_authhmac(td->pubauth, sess.secret, SHA1_DIGEST_SIZE,
			   &sess.enonce, &td->ononce, cont,
			   /* 1S */ sizeof(__be32), &ordinal_be,
			   /* 2S */ SHA1_DIGEST_SIZE, td->encauth,
			   /* 3S */ SHA1_DIGEST_SIZE, td->encauth2,
			   /* 4S */ sizeof(tpm_key), &tpm_key,
			   0, NULL);
	if (ret < 0)
		goto out;

	/* build and send the TPM request packet */
	INIT_BUF(tb);
	store16(tb, TPM_TAG_RQU_AUTH1_COMMAND);
	store32(tb, TPM_DATA_OFFSET + 44 + sizeof(tpm_key) + 45);
	store32(tb, TPM_ORD_CREATEWRAPKEY);
	store32(tb, parent_handle);
	store_s(tb, td->encauth, SHA1_DIGEST_SIZE);
	store_s(tb, td->encauth2, SHA1_DIGEST_SIZE);
	store_s(tb, &tpm_key, sizeof(tpm_key));
	store32(tb, sess.handle);
	store_s(tb, td->ononce.data, TPM_NONCE_SIZE);
	store_8(tb, cont);
	store_s(tb, td->pubauth, SHA1_DIGEST_SIZE);

	ret = tpm_send_dump(chip, tb, "creating key");
	if (ret < 0)
		goto out;

	/* We need to work out how big the TPM_KEY or TPM_KEY12 struct we got
	 * back is.  These structs have several variable-length fields inside
	 * to make parsing more difficult.  However, they are only followed by
	 * fixed-length structs...
	 */
	SET_BUF_OFFSET(tb, TPM_SIZE_OFFSET);
	key_size = LOAD32(tb);
	key_size -= TPM_DATA_OFFSET;
	key_size -= 2 * TPM_NONCE_SIZE + 1;
	if (key_size < sizeof(tpm_key)) {
		ret = -EBADMSG;
		goto out;
	}

	/* Check the HMAC in the response */
	ret = TSS_checkhmac1(tb, ordinal_be, &td->ononce,
			     sess.secret, SHA1_DIGEST_SIZE,
			     /* 3S */ key_size, TPM_DATA_OFFSET,
			     0, NULL);
	if (ret < 0)
		goto out;

	/* Parse the key */
	result = (void *)tb->data + TPM_DATA_OFFSET;
	ret = -EBADMSG;
	if (key_size < sizeof(tpm_key) + be32_to_cpu(tpm_key.parms.rsa.key_length) / 8)
		goto out;
	if (memcmp(result, &tpm_key, offsetof(struct tpm_key, pub.key_length)) != 0)
		goto out;
	if (be32_to_cpu(result->pub.key_length) >
	    be32_to_cpu(tpm_key.parms.rsa.key_length) / 8)
		goto out;

	ret = -ENOMEM;
	wrapped_key = kmalloc(sizeof(struct tpm_wrapped_key) + key_size, GFP_KERNEL);
	if (!wrapped_key)
		goto out;
	wrapped_key->data_len = key_size;
	wrapped_key->pubkey_offset = offsetof(struct tpm_key, pub.key_data);
	wrapped_key->pubkey_len = be32_to_cpu(result->pub.key_length);
	memcpy(wrapped_key->data, result, key_size);
	*_wrapped_key = wrapped_key;
	ret = 0;

out:
	kfree(tb);
	kleave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL_GPL(tpm_create_wrap_key);

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
