// SPDX-License-Identifier: GPL-2.0-or-later
/* RxGK self-testing
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include "ar-internal.h"
#include "rxgk_common.h"

#define VALID(X) \
	({								\
		bool __x = (X);						\
		if (__x) {						\
			pr_warn("!!! TESTINVAL %s:%u\n", __FILE__, __LINE__); \
		}							\
		__x;							\
	})

#define CHECK(X) \
	({								\
		bool __x = (X);						\
		if (__x) {						\
			pr_warn("!!! TESTFAIL %s:%u\n", __FILE__, __LINE__); \
		}							\
		__x;							\
	})

enum which_key {
	TEST_KC, TEST_KE, TEST_KI,
};

static int prep_buf(struct rxgk_buffer *buf)
{
	buf->data = kmalloc(buf->len, GFP_KERNEL);
	if (!buf->data)
		return -ENOMEM;
	return 0;
}

#define PREP_BUF(BUF, LEN)					\
	do {							\
		(BUF)->len = (LEN);				\
		if ((ret = prep_buf((BUF))) < 0)		\
			goto out;				\
	} while(0)

static int load_buf(struct rxgk_buffer *buf, const char *from)
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
	if ((ret = hex2bin(buf->data, from, buf->len)) < 0) {
		VALID(1);
		goto out;
	}
out:
	return ret;
}

#define LOAD_BUF(BUF, FROM) do { if ((ret = load_buf(BUF, FROM)) < 0) goto out; } while(0)

static void clear_buf(struct rxgk_buffer *buf)
{
	kfree(buf->data);
	buf->len = 0;
	buf->data = NULL;
}

/*
 * Perform a pseudo-random function check.
 */
static int rxgk_test_one_prf(const struct rxgk_prf_test *test)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct rxgk_buffer key = {}, octet = {}, result = {}, prf = {};
	int ret;

	pr_notice("Running %s %s\n", gk5e->name, test->name);

	LOAD_BUF(&key,   test->key);
	LOAD_BUF(&octet, test->octet);
	LOAD_BUF(&prf,   test->prf);
	PREP_BUF(&result, gk5e->prf_len);

	if (VALID(result.len != prf.len)) {
		ret = -EINVAL;
		goto out;
	}

	if ((ret = gk5e->scheme->calc_PRF(gk5e, &key, &octet, &result, GFP_KERNEL)) < 0) {
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
static int rxgk_test_key(const struct rxgk_krb5_enctype *gk5e,
			 const struct rxgk_buffer *base_key,
			 const struct rxgk_key_test_one *test,
			 enum which_key which)
{
	struct rxgk_buffer label = {}, key = {}, result = {};
	int ret;
	int (*calc)(const struct rxgk_krb5_enctype *gk5e,
		    const struct rxgk_buffer *TK,
		    const struct rxgk_buffer *usage_constant,
		    struct rxgk_buffer *Kc,
		    gfp_t gfp);

	LOAD_BUF(&label, test->lab);
	LOAD_BUF(&key,   test->key);
	PREP_BUF(&result, key.len);

	switch (which) {
	case TEST_KC: calc = gk5e->scheme->calc_Kc; break;
	case TEST_KE: calc = gk5e->scheme->calc_Ke; break;
	case TEST_KI: calc = gk5e->scheme->calc_Ki; break;
	default:
		VALID(1);
		ret = -EINVAL;
		goto out;
	}

	if ((ret = (*calc)(gk5e, base_key, &label, &result, GFP_KERNEL)) < 0) {
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
	clear_buf(&label);
	clear_buf(&key);
	clear_buf(&result);
	return ret;
}

static int rxgk_test_one_key(const struct rxgk_key_test *test)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct rxgk_buffer base_key = {};
	int ret;

	pr_notice("Running %s %s\n", gk5e->name, test->name);

	LOAD_BUF(&base_key, test->key);

	if ((ret = rxgk_test_key(gk5e, &base_key, &test->Kc, TEST_KC)) < 0)
		goto out;
	if ((ret = rxgk_test_key(gk5e, &base_key, &test->Ke, TEST_KE)) < 0)
		goto out;
	if ((ret = rxgk_test_key(gk5e, &base_key, &test->Ki, TEST_KI)) < 0)
		goto out;

out:
	clear_buf(&base_key);
	return ret;
}

static int rxgk_test_get_Kc(const struct rxgk_mic_test *test,
			    struct crypto_shash **_Kc)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct crypto_shash *shash;
	struct rxgk_buffer K0 = {}, key = {};
	int ret;

	shash = crypto_alloc_shash(gk5e->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
	*_Kc = shash;

	if (test->Kc) {
		LOAD_BUF(&key, test->Kc);
	} else {
		char usage_data[5];
		struct rxgk_buffer usage = { .len = 5, .data = usage_data };
		memcpy(usage_data, &test->usage, 4);
		usage_data[4] = 0x99;
		LOAD_BUF(&K0, test->K0);
		PREP_BUF(&key, gk5e->Kc_len);
		ret = gk5e->scheme->calc_Kc(gk5e, &K0, &usage, &key, GFP_KERNEL);
	}

	ret = crypto_shash_setkey(shash, key.data, key.len);
out:
	clear_buf(&key);
	clear_buf(&K0);
	return ret;
}

static int rxgk_test_get_Ke(const struct rxgk_enc_test *test,
			    struct rxgk_enc_keys *keys)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct crypto_sync_skcipher *ci;
	struct rxgk_buffer K0 = {}, key = {};
	int ret;

	ci = crypto_alloc_sync_skcipher(gk5e->encrypt_name, 0, 0);
	if (IS_ERR(ci))
		return (PTR_ERR(ci) == -ENOENT) ? -ENOPKG : PTR_ERR(ci);
	keys->Ke = ci;

	if (test->Ke) {
		LOAD_BUF(&key, test->Ke);
	} else {
		char usage_data[5];
		struct rxgk_buffer usage = { .len = 5, .data = usage_data };
		memcpy(usage_data, &test->usage, 4);
		usage_data[4] = 0xAA;
		LOAD_BUF(&K0, test->K0);
		PREP_BUF(&key, gk5e->Ke_len);
		ret = gk5e->scheme->calc_Ke(gk5e, &K0, &usage, &key, GFP_KERNEL);
	}

	ret = crypto_sync_skcipher_setkey(ci, key.data, key.len);
out:
	clear_buf(&key);
	clear_buf(&K0);
	return ret;
}

static int rxgk_test_get_Ki(const struct rxgk_enc_test *test,
			    struct rxgk_enc_keys *keys)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct crypto_shash *shash;
	struct rxgk_buffer K0 = {}, key = {};
	int ret;

	shash = crypto_alloc_shash(gk5e->cksum_name, 0, 0);
	if (IS_ERR(shash))
		return (PTR_ERR(shash) == -ENOENT) ? -ENOPKG : PTR_ERR(shash);
	keys->Ki = shash;

	if (test->Ki) {
		LOAD_BUF(&key, test->Ki);
	} else {
		char usage_data[5];
		struct rxgk_buffer usage = { .len = 5, .data = usage_data };
		memcpy(usage_data, &test->usage, 4);
		usage_data[4] = 0x55;
		LOAD_BUF(&K0, test->K0);
		PREP_BUF(&key, gk5e->Ki_len);
		ret = gk5e->scheme->calc_Ki(gk5e, &K0, &usage, &key, GFP_KERNEL);
	}

	ret = crypto_shash_setkey(shash, key.data, key.len);
out:
	clear_buf(&key);
	clear_buf(&K0);
	return ret;
}

/*
 * Generate a packet containing encryption test data.
 */
static struct sk_buff *rxgk_load_enc_packet(const struct rxgk_enc_test *test,
					    const struct rxgk_buffer *plain)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct sk_buff *skb;
	unsigned int conf_len, pad_len, enc_len, ct_len;
	void *p;
	int ret;

	conf_len = strlen(test->conf);
	if (VALID((conf_len & 1) || conf_len / 2 != gk5e->conflen))
		return ERR_PTR(-EINVAL);

	if (gk5e->pad) {
		enc_len = round_up(gk5e->conflen + plain->len, gk5e->blocksize);
		pad_len = enc_len - (gk5e->conflen + plain->len);
	} else {
		enc_len = gk5e->conflen + plain->len;
		pad_len = 0;
	}

	ct_len = strlen(test->ct);
	if (VALID((ct_len & 1) || ct_len / 2 != enc_len + gk5e->cksumlength))
		return ERR_PTR(-EINVAL);
	ct_len = enc_len + gk5e->cksumlength;

	skb = alloc_skb(ct_len, GFP_NOFS);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	p = __skb_put(skb, gk5e->conflen);
	if ((ret = hex2bin(p, test->conf, gk5e->conflen)) < 0)
		goto error;

	__skb_put_data(skb, plain->data, plain->len);
	__skb_put_zero(skb, pad_len + gk5e->cksumlength);
	return skb;

error:
	kfree_skb(skb);
	return ERR_PTR(ret);
}

/*
 * Generate a packet containing checksum test data.
 */
static struct sk_buff *rxgk_load_mic_packet(const struct rxgk_mic_test *test,
					    const struct rxgk_buffer *plain)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct sk_buff *skb;

	skb = alloc_skb(plain->len + gk5e->cksumlength, GFP_NOFS);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	__skb_put_zero(skb, gk5e->cksumlength);
	__skb_put_data(skb, plain->data, plain->len);
	return skb;
}

/*
 * Perform an encryption test.
 */
static int rxgk_test_one_enc(const struct rxgk_enc_test *test)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct rxgk_enc_keys keys = {};
	struct rxgk_buffer plain = {}, ct = {};
	struct sk_buff *skb = NULL;
	unsigned int offset, len;
	u32 abort_code;
	int ret;

	pr_notice("Running %s %s\n", gk5e->name, test->name);

	if ((ret = rxgk_test_get_Ke(test, &keys)) < 0 ||
	    (ret = rxgk_test_get_Ki(test, &keys)) < 0)
		goto out;

	LOAD_BUF(&plain, test->plain);
	LOAD_BUF(&ct, test->ct);

	skb = rxgk_load_enc_packet(test, &plain);
	if (IS_ERR(skb)) {
		ret = PTR_ERR(skb);
		skb = NULL;
		goto out;
	}

	ret = test->gk5e->scheme->encrypt_skb(gk5e, &keys, skb,
					      gk5e->conflen, plain.len, true);
	if (ret < 0) {
		CHECK(1);
		pr_warn("Encryption failed %d\n", ret);
		goto out;
	}

	if (memcmp(skb->data, ct.data, ct.len) != 0) {
		CHECK(1);
		pr_warn("Ciphertext mismatch\n");
		pr_warn("SKB %*phN\n", skb->len, skb->data);
		pr_warn("CT  %*phN\n", ct.len, ct.data);
		ret = -EKEYREJECTED;
		goto out;
	}

	offset = 0;
	len = skb->len;
	ret = test->gk5e->scheme->decrypt_skb(NULL, gk5e, &keys, skb,
					      &offset, &len, &abort_code);
	if (ret < 0) {
		CHECK(1);
		pr_warn("Decryption failed %d\n", ret);
		goto out;
	}

	if (CHECK(len != plain.len))
		goto out;

	if (memcmp(skb->data + offset, plain.data, plain.len) != 0) {
		CHECK(1);
		pr_warn("Plaintext mismatch\n");
		pr_warn("SKB %*phN\n", len, skb->data + offset);
		pr_warn("PT  %*phN\n", plain.len, plain.data);
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = 0;

out:
	kfree_skb(skb);
	clear_buf(&ct);
	clear_buf(&plain);
	rxgk_free_enc_keys(&keys);
	return ret;
}

static int rxgk_test_one_mic(const struct rxgk_mic_test *test)
{
	const struct rxgk_krb5_enctype *gk5e = test->gk5e;
	struct crypto_shash *Kc = NULL;
	struct rxgk_buffer plain = {}, mic = {};
	struct sk_buff *skb = NULL;
	unsigned int offset, len;
	u32 abort_code;
	int ret;

	pr_notice("Running %s %s\n", gk5e->name, test->name);

	if ((ret = rxgk_test_get_Kc(test, &Kc)) < 0)
		goto out;

	LOAD_BUF(&plain, test->plain);
	LOAD_BUF(&mic, test->mic);

	skb = rxgk_load_mic_packet(test, &plain);
	if (IS_ERR(skb)) {
		ret = PTR_ERR(skb);
		skb = NULL;
		goto out;
	}

	ret = test->gk5e->scheme->get_mic_skb(gk5e, Kc, NULL, skb,
					      gk5e->cksumlength, plain.len);
	if (ret < 0) {
		CHECK(1);
		pr_warn("Get MIC failed %d\n", ret);
		goto out;
	}

	if (memcmp(skb->data, mic.data, mic.len) != 0) {
		CHECK(1);
		pr_warn("MIC mismatch\n");
		pr_warn("SKB %*phN\n", skb->len, skb->data);
		pr_warn("MIC %*phN\n", mic.len, mic.data);
		ret = -EKEYREJECTED;
		goto out;
	}

	offset = 0;
	len = skb->len;
	ret = test->gk5e->scheme->verify_mic_skb(NULL, gk5e, Kc, NULL, skb,
						 &offset, &len, &abort_code);
	if (ret < 0) {
		CHECK(1);
		pr_warn("Verify MIC failed %d\n", ret);
		goto out;
	}

	if (CHECK(len != plain.len))
		goto out;

	if (memcmp(skb->data + offset, plain.data, plain.len) != 0) {
		CHECK(1);
		pr_warn("Plaintext mismatch\n");
		pr_warn("SKB %*phN\n", len, skb->data + offset);
		pr_warn("PT  %*phN\n", plain.len, plain.data);
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = 0;

out:
	kfree_skb(skb);
	clear_buf(&mic);
	clear_buf(&plain);
	if (Kc)
		crypto_free_shash(Kc);
	return ret;
}

void rxgk_selftest(void)
{
	bool fail = false;
	int i;

	pr_notice("Running selftests\n");

	for (i = 0; rxgk_prf_tests[i].gk5e; i++)
		fail |= rxgk_test_one_prf(&rxgk_prf_tests[i]) < 0;

	for (i = 0; rxgk_key_tests[i].gk5e; i++)
		fail |= rxgk_test_one_key(&rxgk_key_tests[i]) < 0;

	for (i = 0; rxgk_enc_tests[i].gk5e; i++)
		fail |= rxgk_test_one_enc(&rxgk_enc_tests[i]) < 0;

	for (i = 0; rxgk_mic_tests[i].gk5e; i++)
		fail |= rxgk_test_one_mic(&rxgk_mic_tests[i]) < 0;

	pr_notice("Selftests %s\n", fail ? "failed" : "succeeded");
}
