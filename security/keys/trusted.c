/*
 * Copyright (C) 2010 IBM Corporation
 *
 * Author:
 * David Safford <safford@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * See Documentation/security/keys-trusted-encrypted.txt
 */

#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/string.h>
#include <linux/err.h>
#include <keys/user-type.h>
#include <keys/trusted-type.h>
#include <linux/key-type.h>
#include <linux/rcupdate.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/capability.h>
#include <linux/tpm.h>
#include <linux/tpm_command.h>

#include "trusted.h"

/*
 * Lock a trusted key, by extending a selected PCR.
 *
 * Prevents a trusted key that is sealed to PCRs from being accessed.
 * This uses the tpm driver's extend function.
 */
static int pcrlock(struct tpm_chip *chip, const int pcrnum)
{
	unsigned char hash[SHA1_DIGEST_SIZE];
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	ret = tpm_get_random(chip, hash, SHA1_DIGEST_SIZE);
	if (ret != SHA1_DIGEST_SIZE)
		return ret;
	return tpm_pcr_extend(chip, pcrnum, hash) ? -EINVAL : 0;
}

/*
 * Have the TPM seal(encrypt) the symmetric key
 */
static int key_seal(struct tpm_chip *chip,
		    struct trusted_key_payload *p,
		    struct trusted_key_options *o)
{
	struct tpm_buf *tb;
	int ret;

	tb = kzalloc(sizeof *tb, GFP_KERNEL);
	if (!tb)
		return -ENOMEM;

	/* include migratable flag at end of sealed key */
	p->key[p->key_len] = p->migratable;

	ret = tpm_seal(chip, tb, o->keytype, o->keyhandle, o->keyauth,
		       p->key, p->key_len + 1, p->blob, &p->blob_len,
		       o->blobauth, o->pcrinfo, o->pcrinfo_len);
	if (ret < 0)
		pr_info("trusted_key: srkseal failed (%d)\n", ret);

	kfree(tb);
	return ret;
}

/*
 * Have the TPM unseal(decrypt) the symmetric key
 */
static int key_unseal(struct tpm_chip *chip,
		      struct trusted_key_payload *p,
		      struct trusted_key_options *o)
{
	struct tpm_buf *tb;
	int ret;

	tb = kzalloc(sizeof *tb, GFP_KERNEL);
	if (!tb)
		return -ENOMEM;

	ret = tpm_unseal(chip, tb, o->keyhandle, o->keyauth,
			 p->blob, p->blob_len,
			 o->blobauth, p->key, &p->key_len);
	if (ret < 0)
		pr_info("trusted_key: srkunseal failed (%d)\n", ret);
	else
		/* pull migratable flag out of sealed key */
		p->migratable = p->key[--p->key_len];

	kfree(tb);
	return ret;
}

enum {
	Opt_err = -1,
	Opt_new, Opt_load, Opt_update,
	Opt_keyhandle, Opt_keyauth, Opt_blobauth,
	Opt_pcrinfo, Opt_pcrlock, Opt_migratable
};

static const match_table_t key_tokens = {
	{Opt_new, "new"},
	{Opt_load, "load"},
	{Opt_update, "update"},
	{Opt_keyhandle, "keyhandle=%s"},
	{Opt_keyauth, "keyauth=%s"},
	{Opt_blobauth, "blobauth=%s"},
	{Opt_pcrinfo, "pcrinfo=%s"},
	{Opt_pcrlock, "pcrlock=%s"},
	{Opt_migratable, "migratable=%s"},
	{Opt_err, NULL}
};

/* can have zero or more token= options */
static int getoptions(char *c, struct trusted_key_payload *pay,
		      struct trusted_key_options *opt)
{
	substring_t args[MAX_OPT_ARGS];
	char *p = c;
	int token;
	int res;
	unsigned long handle;
	unsigned long lock;

	while ((p = strsep(&c, " \t"))) {
		if (*p == '\0' || *p == ' ' || *p == '\t')
			continue;
		token = match_token(p, key_tokens, args);

		switch (token) {
		case Opt_pcrinfo:
			opt->pcrinfo_len = strlen(args[0].from) / 2;
			if (opt->pcrinfo_len > MAX_PCRINFO_SIZE)
				return -EINVAL;
			res = hex2bin(opt->pcrinfo, args[0].from,
				      opt->pcrinfo_len);
			if (res < 0)
				return -EINVAL;
			break;
		case Opt_keyhandle:
			res = kstrtoul(args[0].from, 16, &handle);
			if (res < 0)
				return -EINVAL;
			opt->keytype = SEAL_keytype;
			opt->keyhandle = handle;
			break;
		case Opt_keyauth:
			if (strlen(args[0].from) != 2 * SHA1_DIGEST_SIZE)
				return -EINVAL;
			res = hex2bin(opt->keyauth, args[0].from,
				      SHA1_DIGEST_SIZE);
			if (res < 0)
				return -EINVAL;
			break;
		case Opt_blobauth:
			if (strlen(args[0].from) != 2 * SHA1_DIGEST_SIZE)
				return -EINVAL;
			res = hex2bin(opt->blobauth, args[0].from,
				      SHA1_DIGEST_SIZE);
			if (res < 0)
				return -EINVAL;
			break;
		case Opt_migratable:
			if (*args[0].from == '0')
				pay->migratable = 0;
			else
				return -EINVAL;
			break;
		case Opt_pcrlock:
			res = kstrtoul(args[0].from, 10, &lock);
			if (res < 0)
				return -EINVAL;
			opt->pcrlock = lock;
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * datablob_parse - parse the keyctl data and fill in the
 * 		    payload and options structures
 *
 * On success returns 0, otherwise -EINVAL.
 */
static int datablob_parse(char *datablob, struct trusted_key_payload *p,
			  struct trusted_key_options *o)
{
	substring_t args[MAX_OPT_ARGS];
	long keylen;
	int ret = -EINVAL;
	int key_cmd;
	char *c;

	/* main command */
	c = strsep(&datablob, " \t");
	if (!c)
		return -EINVAL;
	key_cmd = match_token(c, key_tokens, args);
	switch (key_cmd) {
	case Opt_new:
		/* first argument is key size */
		c = strsep(&datablob, " \t");
		if (!c)
			return -EINVAL;
		ret = kstrtol(c, 10, &keylen);
		if (ret < 0 || keylen < MIN_KEY_SIZE || keylen > MAX_KEY_SIZE)
			return -EINVAL;
		p->key_len = keylen;
		ret = getoptions(datablob, p, o);
		if (ret < 0)
			return ret;
		ret = Opt_new;
		break;
	case Opt_load:
		/* first argument is sealed blob */
		c = strsep(&datablob, " \t");
		if (!c)
			return -EINVAL;
		p->blob_len = strlen(c) / 2;
		if (p->blob_len > MAX_BLOB_SIZE)
			return -EINVAL;
		ret = hex2bin(p->blob, c, p->blob_len);
		if (ret < 0)
			return -EINVAL;
		ret = getoptions(datablob, p, o);
		if (ret < 0)
			return ret;
		ret = Opt_load;
		break;
	case Opt_update:
		/* all arguments are options */
		ret = getoptions(datablob, p, o);
		if (ret < 0)
			return ret;
		ret = Opt_update;
		break;
	case Opt_err:
		return -EINVAL;
		break;
	}
	return ret;
}

static struct trusted_key_options *trusted_options_alloc(void)
{
	struct trusted_key_options *options;

	options = kzalloc(sizeof *options, GFP_KERNEL);
	if (options) {
		/* set any non-zero defaults */
		options->keytype = SRK_keytype;
		options->keyhandle = SRKHANDLE;
	}
	return options;
}

static struct trusted_key_payload *trusted_payload_alloc(struct key *key)
{
	struct trusted_key_payload *p = NULL;
	int ret;

	ret = key_payload_reserve(key, sizeof *p);
	if (ret < 0)
		return p;
	p = kzalloc(sizeof *p, GFP_KERNEL);
	if (p)
		p->migratable = 1; /* migratable by default */
	return p;
}

/*
 * trusted_instantiate - create a new trusted key
 *
 * Unseal an existing trusted blob or, for a new key, get a
 * random key, then seal and create a trusted key-type key,
 * adding it to the specified keyring.
 *
 * On success, return 0. Otherwise return errno.
 */
static int trusted_instantiate(struct key *key,
			       struct key_preparsed_payload *prep)
{
	struct trusted_key_payload *payload = NULL;
	struct trusted_key_options *options = NULL;
	struct tpm_chip *chip = NULL;
	size_t datalen = prep->datalen;
	char *datablob;
	int ret = 0;
	int key_cmd;
	size_t key_len;

	if (datalen <= 0 || datalen > 32767 || !prep->data)
		return -EINVAL;

	datablob = kmalloc(datalen + 1, GFP_KERNEL);
	if (!datablob)
		return -ENOMEM;
	memcpy(datablob, prep->data, datalen);
	datablob[datalen] = '\0';

	options = trusted_options_alloc();
	if (!options) {
		ret = -ENOMEM;
		goto out;
	}
	payload = trusted_payload_alloc(key);
	if (!payload) {
		ret = -ENOMEM;
		goto out;
	}

	key_cmd = datablob_parse(datablob, payload, options);
	if (key_cmd < 0) {
		ret = key_cmd;
		goto out;
	}

	dump_payload(payload);
	dump_options(options);

	ret = -ENODEV;
	chip = tpm_chip_find_get(TPM_ANY_NUM);
	if (!chip)
		goto out;

	switch (key_cmd) {
	case Opt_load:
		ret = key_unseal(chip, payload, options);
		dump_payload(payload);
		dump_options(options);
		if (ret < 0)
			pr_info("trusted_key: key_unseal failed (%d)\n", ret);
		break;
	case Opt_new:
		key_len = payload->key_len;
		ret = tpm_get_random(chip, payload->key, key_len);
		if (ret != key_len) {
			pr_info("trusted_key: key_create failed (%d)\n", ret);
			goto out;
		}
		ret = key_seal(chip, payload, options);
		if (ret < 0)
			pr_info("trusted_key: key_seal failed (%d)\n", ret);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (!ret && options->pcrlock)
		ret = pcrlock(chip, options->pcrlock);
out:
	tpm_chip_put(chip);
	kfree(datablob);
	kfree(options);
	if (!ret)
		rcu_assign_keypointer(key, payload);
	else
		kfree(payload);
	return ret;
}

static void trusted_rcu_free(struct rcu_head *rcu)
{
	struct trusted_key_payload *p;

	p = container_of(rcu, struct trusted_key_payload, rcu);
	memset(p->key, 0, p->key_len);
	kfree(p);
}

/*
 * trusted_update - reseal an existing key with new PCR values
 */
static int trusted_update(struct key *key, struct key_preparsed_payload *prep)
{
	struct trusted_key_payload *p = key->payload.data;
	struct trusted_key_payload *new_p;
	struct trusted_key_options *new_o;
	struct tpm_chip *chip = NULL;
	size_t datalen = prep->datalen;
	char *datablob;
	int ret = 0;

	if (!p->migratable)
		return -EPERM;
	if (datalen <= 0 || datalen > 32767 || !prep->data)
		return -EINVAL;

	datablob = kmalloc(datalen + 1, GFP_KERNEL);
	if (!datablob)
		return -ENOMEM;
	new_o = trusted_options_alloc();
	if (!new_o) {
		ret = -ENOMEM;
		goto out;
	}
	new_p = trusted_payload_alloc(key);
	if (!new_p) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(datablob, prep->data, datalen);
	datablob[datalen] = '\0';
	ret = datablob_parse(datablob, new_p, new_o);
	if (ret != Opt_update) {
		ret = -EINVAL;
		kfree(new_p);
		goto out;
	}

	/* copy old key values, and reseal with new pcrs */
	new_p->migratable = p->migratable;
	new_p->key_len = p->key_len;
	memcpy(new_p->key, p->key, p->key_len);
	dump_payload(p);
	dump_payload(new_p);

	ret = -ENODEV;
	chip = tpm_chip_find_get(TPM_ANY_NUM);
	if (!chip)
		goto out;

	ret = key_seal(chip, new_p, new_o);
	if (ret < 0) {
		pr_info("trusted_key: key_seal failed (%d)\n", ret);
		kfree(new_p);
		goto out;
	}
	if (new_o->pcrlock) {
		ret = pcrlock(chip, new_o->pcrlock);
		if (ret < 0) {
			pr_info("trusted_key: pcrlock failed (%d)\n", ret);
			kfree(new_p);
			goto out;
		}
	}
	rcu_assign_keypointer(key, new_p);
	call_rcu(&p->rcu, trusted_rcu_free);
out:
	tpm_chip_put(chip);
	kfree(datablob);
	kfree(new_o);
	return ret;
}

/*
 * trusted_read - copy the sealed blob data to userspace in hex.
 * On success, return to userspace the trusted key datablob size.
 */
static long trusted_read(const struct key *key, char __user *buffer,
			 size_t buflen)
{
	struct trusted_key_payload *p;
	char *ascii_buf;
	char *bufp;
	int i;

	p = rcu_dereference_key(key);
	if (!p)
		return -EINVAL;
	if (!buffer || buflen <= 0)
		return 2 * p->blob_len;
	ascii_buf = kmalloc(2 * p->blob_len, GFP_KERNEL);
	if (!ascii_buf)
		return -ENOMEM;

	bufp = ascii_buf;
	for (i = 0; i < p->blob_len; i++)
		bufp = hex_byte_pack(bufp, p->blob[i]);
	if ((copy_to_user(buffer, ascii_buf, 2 * p->blob_len)) != 0) {
		kfree(ascii_buf);
		return -EFAULT;
	}
	kfree(ascii_buf);
	return 2 * p->blob_len;
}

/*
 * trusted_destroy - before freeing the key, clear the decrypted data
 */
static void trusted_destroy(struct key *key)
{
	struct trusted_key_payload *p = key->payload.data;

	if (!p)
		return;
	memset(p->key, 0, p->key_len);
	kfree(key->payload.data);
}

struct key_type key_type_trusted = {
	.name = "trusted",
	.instantiate = trusted_instantiate,
	.update = trusted_update,
	.destroy = trusted_destroy,
	.describe = user_describe,
	.read = trusted_read,
};

EXPORT_SYMBOL_GPL(key_type_trusted);

static int __init init_trusted(void)
{
	int ret;

	ret = tpm_library_use();
	if (ret < 0)
		return ret;
	ret = register_key_type(&key_type_trusted);
	if (ret < 0)
		tpm_library_unuse();
	return ret;
}

static void __exit cleanup_trusted(void)
{
	unregister_key_type(&key_type_trusted);
	tpm_library_unuse();
}

late_initcall(init_trusted);
module_exit(cleanup_trusted);

MODULE_LICENSE("GPL");
