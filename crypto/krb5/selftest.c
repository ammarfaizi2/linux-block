// SPDX-License-Identifier: GPL-2.0-or-later
/* Kerberos library self-testing
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include "internal.h"

#define VALID(X) \
	({								\
		bool __x = (X);						\
		if (__x) {						\
			pr_warn("!!! TESTINVAL %s:%u\n", __FILE__, __LINE__); \
			ret = -EBADMSG;					\
		}							\
		__x;							\
	})

#define CHECK(X) \
	({								\
		bool __x = (X);						\
		if (__x) {						\
			pr_warn("!!! TESTFAIL %s:%u\n", __FILE__, __LINE__); \
			ret = -EBADMSG;					\
		}							\
		__x;							\
	})

enum which_key {
	TEST_KC, TEST_KE, TEST_KI,
};

static int prep_buf(struct krb5_buffer *buf)
{
	buf->data = kmalloc(buf->len, GFP_KERNEL);
	if (!buf->data)
		return -ENOMEM;
	return 0;
}

#define PREP_BUF(BUF, LEN)					\
	do {							\
		(BUF)->len = (LEN);				\
		ret = prep_buf((BUF));				\
		if (ret < 0)					\
			goto out;				\
	} while (0)

static int load_buf(struct krb5_buffer *buf, const char *from)
{
	size_t len = strlen(from);
	int ret;

	if (len > 1 && from[0] == '\'') {
		PREP_BUF(buf, len - 1);
		memcpy(buf->data, from + 1, len - 1);
		ret = 0;
		goto out;
	}

	if (VALID(len & 1))
		return -EINVAL;

	PREP_BUF(buf, len / 2);
	ret = hex2bin(buf->data, from, buf->len);
	if (ret < 0) {
		VALID(1);
		goto out;
	}
out:
	return ret;
}

#define LOAD_BUF(BUF, FROM) do { ret = load_buf(BUF, FROM); if (ret < 0) goto out; } while (0)

static void clear_buf(struct krb5_buffer *buf)
{
	kfree(buf->data);
	buf->len = 0;
	buf->data = NULL;
}

/*
 * Perform a pseudo-random function check.
 */
static int krb5_test_one_prf(const struct krb5_prf_test *test)
{
	const struct krb5_enctype *krb5 = test->krb5;
	struct krb5_buffer key = {}, octet = {}, result = {}, prf = {};
	int ret;

	pr_notice("Running %s %s\n", krb5->name, test->name);

	LOAD_BUF(&key,   test->key);
	LOAD_BUF(&octet, test->octet);
	LOAD_BUF(&prf,   test->prf);
	PREP_BUF(&result, krb5->prf_len);

	if (VALID(result.len != prf.len)) {
		ret = -EINVAL;
		goto out;
	}

	ret = krb5->profile->calc_PRF(krb5, &key, &octet, &result, GFP_KERNEL);
	if (ret < 0) {
		CHECK(1);
		pr_warn("PRF calculation failed %d\n", ret);
		goto out;
	}

	if (memcmp(result.data, prf.data, result.len) != 0) {
		CHECK(1);
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = 0;

out:
	clear_buf(&result);
	clear_buf(&octet);
	clear_buf(&key);
	return ret;
}

/*
 * Perform a key derivation check.
 */
static int krb5_test_key(const struct krb5_enctype *krb5,
			 const struct krb5_buffer *base_key,
			 const struct krb5_key_test_one *test,
			 enum which_key which)
{
	struct krb5_buffer key = {}, result = {};
	int ret;

	LOAD_BUF(&key,   test->key);
	PREP_BUF(&result, key.len);

	switch (which) {
	case TEST_KC:
		ret = crypto_krb5_get_Kc(krb5, base_key, test->use, &result,
					 NULL, GFP_KERNEL);
		break;
	case TEST_KE:
		ret = crypto_krb5_get_Ke(krb5, base_key, test->use, &result,
					 NULL, GFP_KERNEL);
		break;
	case TEST_KI:
		ret = crypto_krb5_get_Ki(krb5, base_key, test->use, &result,
					 NULL, GFP_KERNEL);
		break;
	default:
		VALID(1);
		ret = -EINVAL;
		goto out;
	}

	if (ret < 0) {
		CHECK(1);
		pr_warn("Key derivation failed %d\n", ret);
		goto out;
	}

	if (memcmp(result.data, key.data, result.len) != 0) {
		CHECK(1);
		ret = -EKEYREJECTED;
		goto out;
	}

out:
	clear_buf(&key);
	clear_buf(&result);
	return ret;
}

static int krb5_test_one_key(const struct krb5_key_test *test)
{
	const struct krb5_enctype *krb5 = test->krb5;
	struct krb5_buffer base_key = {};
	int ret;

	pr_notice("Running %s %s\n", krb5->name, test->name);

	LOAD_BUF(&base_key, test->key);

	ret = krb5_test_key(krb5, &base_key, &test->Kc, TEST_KC);
	if (ret < 0)
		goto out;
	ret = krb5_test_key(krb5, &base_key, &test->Ke, TEST_KE);
	if (ret < 0)
		goto out;
	ret = krb5_test_key(krb5, &base_key, &test->Ki, TEST_KI);
	if (ret < 0)
		goto out;

out:
	clear_buf(&base_key);
	return ret;
}

static int krb5_test_get_Kc(const struct krb5_mic_test *test,
			    struct crypto_shash **_Kc)
{
	const struct krb5_enctype *krb5 = test->krb5;
	struct crypto_shash *shash;
	struct krb5_buffer K0 = {}, key = {};
	int ret;

	shash = crypto_alloc_shash(krb5->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
	*_Kc = shash;

	if (test->Kc) {
		LOAD_BUF(&key, test->Kc);
	} else {
		char usage_data[5];
		struct krb5_buffer usage = { .len = 5, .data = usage_data };

		memcpy(usage_data, &test->usage, 4);
		usage_data[4] = 0x99;
		LOAD_BUF(&K0, test->K0);
		PREP_BUF(&key, krb5->Kc_len);
		ret = krb5->profile->calc_Kc(krb5, &K0, &usage, &key, GFP_KERNEL);
	}

	ret = crypto_shash_setkey(shash, key.data, key.len);
out:
	clear_buf(&key);
	clear_buf(&K0);
	return ret;
}

static int krb5_test_get_Ke(const struct krb5_enc_test *test,
			    struct krb5_enc_keys *keys)
{
	const struct krb5_enctype *krb5 = test->krb5;
	struct crypto_sync_skcipher *ci;
	struct krb5_buffer K0 = {}, key = {};
	int ret;

	ci = crypto_alloc_sync_skcipher(krb5->encrypt_name, 0, 0);
	if (IS_ERR(ci))
		return (PTR_ERR(ci) == -ENOENT) ? -ENOPKG : PTR_ERR(ci);
	keys->Ke = ci;

	if (test->Ke) {
		LOAD_BUF(&key, test->Ke);
	} else {
		char usage_data[5];
		struct krb5_buffer usage = { .len = 5, .data = usage_data };

		memcpy(usage_data, &test->usage, 4);
		usage_data[4] = 0xAA;
		LOAD_BUF(&K0, test->K0);
		PREP_BUF(&key, krb5->Ke_len);
		ret = krb5->profile->calc_Ke(krb5, &K0, &usage, &key, GFP_KERNEL);
	}

	ret = crypto_sync_skcipher_setkey(ci, key.data, key.len);
out:
	clear_buf(&key);
	clear_buf(&K0);
	return ret;
}

static int krb5_test_get_Ki(const struct krb5_enc_test *test,
			    struct krb5_enc_keys *keys)
{
	const struct krb5_enctype *krb5 = test->krb5;
	struct crypto_shash *shash;
	struct krb5_buffer K0 = {}, key = {};
	int ret;

	shash = crypto_alloc_shash(krb5->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
	keys->Ki = shash;

	if (test->Ki) {
		LOAD_BUF(&key, test->Ki);
	} else {
		char usage_data[5];
		struct krb5_buffer usage = { .len = 5, .data = usage_data };

		memcpy(usage_data, &test->usage, 4);
		usage_data[4] = 0x55;
		LOAD_BUF(&K0, test->K0);
		PREP_BUF(&key, krb5->Ki_len);
		ret = krb5->profile->calc_Ki(krb5, &K0, &usage, &key, GFP_KERNEL);
	}

	ret = crypto_shash_setkey(shash, key.data, key.len);
out:
	clear_buf(&key);
	clear_buf(&K0);
	return ret;
}

/*
 * Generate a buffer containing encryption test data.
 */
static int krb5_load_enc_buf(const struct krb5_enc_test *test,
			     const struct krb5_buffer *plain,
			     void *buf)
{
	const struct krb5_enctype *krb5 = test->krb5;
	unsigned int conf_len, enc_len, ct_len;
	int ret;

	conf_len = strlen(test->conf);
	if (VALID((conf_len & 1) || conf_len / 2 != krb5->conf_len))
		return -EINVAL;

	if (krb5->pad)
		enc_len = round_up(krb5->conf_len + plain->len, krb5->block_len);
	else
		enc_len = krb5->conf_len + plain->len;

	ct_len = strlen(test->ct);
	if (VALID((ct_len & 1) || ct_len / 2 != enc_len + krb5->cksum_len))
		return -EINVAL;
	ct_len = enc_len + krb5->cksum_len;

	ret = hex2bin(buf, test->conf, krb5->conf_len);
	if (ret < 0)
		return ret;
	buf += krb5->conf_len;
	memcpy(buf, plain->data, plain->len);
	return 0;
}

/*
 * Load checksum test data into a buffer.
 */
static int krb5_load_mic_buf(const struct krb5_mic_test *test,
			     const struct krb5_buffer *plain,
			     void *buf)
{
	const struct krb5_enctype *krb5 = test->krb5;

	memcpy(buf + krb5->cksum_len, plain->data, plain->len);
	return 0;
}

/*
 * Perform an encryption test.
 */
static int krb5_test_one_enc(const struct krb5_enc_test *test, void *buf)
{
	const struct krb5_enctype *krb5 = test->krb5;
	struct krb5_enc_keys keys = {};
	struct krb5_buffer plain = {}, ct = {};
	struct scatterlist sg[1];
	size_t offset, len;
	int ret, error_code;

	pr_notice("Running %s %s\n", krb5->name, test->name);

	ret = krb5_test_get_Ke(test, &keys);
	if (ret < 0)
		goto out;
	ret = krb5_test_get_Ki(test, &keys);
	if (ret < 0)
		goto out;

	LOAD_BUF(&plain, test->plain);
	LOAD_BUF(&ct, test->ct);

	ret = krb5_load_enc_buf(test, &plain, buf);
	if (ret < 0)
		goto out;

	sg_init_one(sg, buf, 1024);
	ret = crypto_krb5_encrypt(krb5, &keys, sg, 1, 1024,
				  krb5->conf_len, plain.len, true);
	if (ret < 0) {
		CHECK(1);
		pr_warn("Encryption failed %d\n", ret);
		goto out;
	}
	len = ret;

	if (CHECK(len != ct.len)) {
		pr_warn("Encrypted length mismatch %zu != %u\n", len, ct.len);
		goto out;
	}

	if (memcmp(buf, ct.data, ct.len) != 0) {
		CHECK(1);
		pr_warn("Ciphertext mismatch\n");
		pr_warn("BUF %*phN\n", ct.len, buf);
		pr_warn("CT  %*phN\n", ct.len, ct.data);
		ret = -EKEYREJECTED;
		goto out;
	}

	offset = 0;
	ret = crypto_krb5_decrypt(krb5, &keys, sg, 1, &offset, &len, &error_code);
	if (ret < 0) {
		CHECK(1);
		pr_warn("Decryption failed %d\n", ret);
		goto out;
	}

	if (CHECK(len != plain.len))
		goto out;

	if (memcmp(buf + offset, plain.data, plain.len) != 0) {
		CHECK(1);
		pr_warn("Plaintext mismatch\n");
		pr_warn("BUF %*phN\n", plain.len, buf + offset);
		pr_warn("PT  %*phN\n", plain.len, plain.data);
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = 0;

out:
	clear_buf(&ct);
	clear_buf(&plain);
	crypto_krb5_free_enc_keys(&keys);
	return ret;
}

static int krb5_test_one_mic(const struct krb5_mic_test *test, void *buf)
{
	const struct krb5_enctype *krb5 = test->krb5;
	struct crypto_shash *Kc = NULL;
	struct scatterlist sg[1];
	struct krb5_buffer plain = {}, mic = {};
	size_t offset, len;
	int ret, error_code;

	pr_notice("Running %s %s\n", krb5->name, test->name);

	ret = krb5_test_get_Kc(test, &Kc);
	if (ret < 0)
		goto out;

	LOAD_BUF(&plain, test->plain);
	LOAD_BUF(&mic, test->mic);

	ret = krb5_load_mic_buf(test, &plain, buf);
	if (ret < 0)
		goto out;

	sg_init_one(sg, buf, 1024);

	ret = crypto_krb5_get_mic(krb5, Kc, NULL, sg, 1, 1024,
				  krb5->cksum_len, plain.len);
	if (ret < 0) {
		CHECK(1);
		pr_warn("Get MIC failed %d\n", ret);
		goto out;
	}
	len = ret;

	if (CHECK(len != plain.len + mic.len)) {
		pr_warn("MIC length mismatch %zu != %u\n", len, plain.len + mic.len);
		goto out;
	}

	if (memcmp(buf, mic.data, mic.len) != 0) {
		CHECK(1);
		pr_warn("MIC mismatch\n");
		pr_warn("BUF %*phN\n", mic.len, buf);
		pr_warn("MIC %*phN\n", mic.len, mic.data);
		ret = -EKEYREJECTED;
		goto out;
	}

	offset = 0;
	ret = crypto_krb5_verify_mic(krb5, Kc, NULL, sg, 1,
				     &offset, &len, &error_code);
	if (ret < 0) {
		CHECK(1);
		pr_warn("Verify MIC failed %d\n", ret);
		goto out;
	}

	if (CHECK(len != plain.len))
		goto out;
	if (CHECK(offset != mic.len))
		goto out;

	if (memcmp(buf + offset, plain.data, plain.len) != 0) {
		CHECK(1);
		pr_warn("Plaintext mismatch\n");
		pr_warn("BUF %*phN\n", plain.len, buf + offset);
		pr_warn("PT  %*phN\n", plain.len, plain.data);
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = 0;

out:
	clear_buf(&mic);
	clear_buf(&plain);
	if (Kc)
		crypto_free_shash(Kc);
	return ret;
}

int krb5_selftest(void)
{
	void *buf;
	int ret = 0, i;

	buf = kmalloc(4096, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pr_notice("\n");
	pr_notice("Running selftests\n");

	for (i = 0; krb5_prf_tests[i].krb5; i++) {
		ret = krb5_test_one_prf(&krb5_prf_tests[i]);
		if (ret < 0)
			goto out;
	}

	for (i = 0; krb5_key_tests[i].krb5; i++) {
		ret = krb5_test_one_key(&krb5_key_tests[i]);
		if (ret < 0)
			goto out;
	}

	for (i = 0; krb5_enc_tests[i].krb5; i++) {
		memset(buf, 0x5a, 4096);
		ret = krb5_test_one_enc(&krb5_enc_tests[i], buf);
		if (ret < 0)
			goto out;
	}

	for (i = 0; krb5_mic_tests[i].krb5; i++) {
		memset(buf, 0x5a, 4096);
		ret = krb5_test_one_mic(&krb5_mic_tests[i], buf);
		if (ret < 0)
			goto out;
	}

out:
	pr_notice("Selftests %s\n", ret == 0 ? "succeeded" : "failed");
	kfree(buf);
	return ret;
}
