/* Instantiate a TPM key.
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#define DEBUG
#define pr_fmt(fmt) "TPKP: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/tpm.h>
#include <linux/parser.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include "asymmetric_keys.h"
#include "tpm_key.h"


enum tpm_key_create_token {
	opt_crt_err = -1,
	opt_crt_parent,
	opt_crt_keyauth,
};

static const match_table_t tpm_key_create_tokens = {
	{ opt_crt_parent,	"parent=%x,%s"},
	{ opt_crt_keyauth,	"keyauth=%s"},
	{ opt_crt_err,		NULL}
};

/*
 * Attempt to parse a key creation request.
 */
static int tpm_key_create(struct tpm_asymmetric_key *key, char *data)
{
	enum tpm_key_create_token token;
	struct tpm_chip *chip;
	unsigned long tmp, got = 0;
	substring_t args[MAX_OPT_ARGS];
	uint32_t key_handle;
	char *p;
	int ret;

	pr_devel("==>%s(,%s)\n", __func__, data);

	while ((p = strsep(&data, " \t"))) {
		if (*p == '\0' || *p == ' ' || *p == '\t')
			continue;
		token = match_token(p, tpm_key_create_tokens, args);
		switch (token) {
		case opt_crt_parent:
			pr_devel("parent %ld %ld\n",
				 args[0].to - args[0].from,
				 args[1].to - args[1].from);
			*args[0].to = 0;
			ret = kstrtoul(args[0].from, 16, &tmp);
			if (ret < 0) {
				pr_devel("bad parent handle\n");
				return -EINVAL;
			}
			key->parent_tpm_handle = tmp;
			if (args[1].to - args[1].from != TPM_DIGEST_SIZE * 2) {
				pr_devel("parent auth wrong size\n");
				return -EINVAL;
			}
			if (hex2bin(key->parent_authdata, args[1].from,
				    TPM_DIGEST_SIZE) < 0) {
				pr_devel("parent auth bad hex\n");
				return -EINVAL;
			}
			break;

		case opt_crt_keyauth:
			pr_devel("keyauth\n");
			if (args[1].to - args[1].from != TPM_DIGEST_SIZE * 2)
				return -EINVAL;
			if (hex2bin(key->parent_authdata, args[1].from,
				    TPM_DIGEST_SIZE) < 0)
				return -EINVAL;
			break;

		case opt_crt_err:
			pr_devel("Unknown token %s\n", p);
			return -EINVAL;
		}
		got |= 1 << token;
	}

	if ((got & 3) != 3) {
		pr_devel("Missing mandatory args\n");
		return -EINVAL;
	}

	chip = tpm_chip_find_get(TPM_ANY_NUM);
	if (!chip)
		return -ENODEV;

	/* Create a key and retrieve the partially encrypted blob. */
	ret = tpm_create_wrap_key(chip, TPM_ET_SRK, key->parent_tpm_handle,
				  key->parent_authdata,
				  key->key_authdata,
				  NULL,
				  &key->wrapped_key);
	if (ret == -EBADMSG)
		ret = -EIO;

	/* Attempt to load the key back as a check */
	ret = tpm_load_key2(chip, TPM_ET_SRK, key->parent_tpm_handle,
			    key->parent_authdata, key->wrapped_key,
			    &key_handle);
	if (ret != 0) {
		pr_devel("Couldn't load key back\n");
		goto out;
	}

	ret = tpm_flush_specific(chip, key_handle, TPM_RT_KEY);
	if (ret != 0)
		pr_devel("Couldn't flush key handle\n");

out:
	tpm_chip_put(chip);
	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}

/*
 * Attempt to parse a data blob for a key as a TPM key specification.
 *
 * We expect one of the following in the prep data:
 *
 *	tpm_create parent=<key>,<auth> keyauth=<hex> [options...]
 *	tpm_load parent=<key>,<auth> data=<hex> [options...]
 */
static int tpm_key_preparse(struct key_preparsed_payload *prep)
{
	struct tpm_asymmetric_key *key;
	char *data;
	int ret;

	pr_devel("==>%s()\n", __func__);

	ret = tpm_library_use();
	if (ret < 0)
		goto out;

	ret = -ENOMEM;
	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		goto out_free_tpmlib;
	data = kmalloc(prep->datalen + 1, GFP_KERNEL);
	if (!data)
		goto out_free_key;

	memcpy(data, prep->data, prep->datalen);
	data[prep->datalen] = 0;
	if (memcmp(data, "tpm_create ", 11) == 0) {
		ret = tpm_key_create(key, data + 11);
	} else {
		ret = -EBADMSG;
		goto out_free_data;
	}

	/* We're pinning the module by being linked against it */
	__module_get(tpm_key_subtype.owner);
	prep->type_data[0] = &tpm_key_subtype;
	//prep->type_data[1] = kids;
	prep->payload[0] = key;
	//prep->description = desc;
	prep->quotalen = 100;
	key = NULL;
	tpm_library_use();

out_free_data:
	kfree(data);
out_free_key:
	kfree(key);
out_free_tpmlib:
	tpm_library_unuse();
out:
	return ret;
}

static struct asymmetric_key_parser tpm_key_parser = {
	.owner	= THIS_MODULE,
	.name	= "tpm",
	.parse	= tpm_key_preparse,
};

/*
 * Module stuff
 */
static int __init tpm_key_init(void)
{
	return register_asymmetric_key_parser(&tpm_key_parser);
}

static void __exit tpm_key_exit(void)
{
	unregister_asymmetric_key_parser(&tpm_key_parser);
}

module_init(tpm_key_init);
module_exit(tpm_key_exit);

MODULE_DESCRIPTION("TPM key parser");
MODULE_LICENSE("GPL");
