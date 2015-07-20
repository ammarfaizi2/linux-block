/* In-software asymmetric public-key crypto subtype
 *
 * See Documentation/crypto/asymmetric-keys.txt
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKEY: "fmt
#include <linux/module.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <keys/asymmetric-subtype.h>
#include "public_key.h"

MODULE_LICENSE("GPL");

const char *const pkey_algo_name[PKEY_ALGO__LAST] = {
	[PKEY_ALGO_DSA]		= "DSA",
	[PKEY_ALGO_RSA]		= "RSA",
};
EXPORT_SYMBOL_GPL(pkey_algo_name);

const struct public_key_algorithm *pkey_algo[PKEY_ALGO__LAST] = {
#if defined(CONFIG_PUBLIC_KEY_ALGO_RSA) || \
	defined(CONFIG_PUBLIC_KEY_ALGO_RSA_MODULE)
	[PKEY_ALGO_RSA]		= &RSA_public_key_algorithm,
#endif
};
EXPORT_SYMBOL_GPL(pkey_algo);

const char *const pkey_id_type_name[PKEY_ID_TYPE__LAST] = {
	[PKEY_ID_PGP]		= "PGP",
	[PKEY_ID_X509]		= "X509",
	[PKEY_ID_PKCS7]		= "PKCS#7",
};
EXPORT_SYMBOL_GPL(pkey_id_type_name);

static const char *const key_usage_restrictions[NR__KEY_USAGE_RESTRICTIONS] = {
	[KEY_USAGE_NOT_SPECIFIED]		= "unrestricted",
	[KEY_RESTRICTED_USAGE]			= "unspecified",
	[KEY_RESTRICTED_TO_OTHER]		= "other use",
	[KEY_RESTRICTED_TO_MODULE_SIGNING]	= "module sig",
	[KEY_RESTRICTED_TO_FIRMWARE_SIGNING]	= "firmware sig",
	[KEY_RESTRICTED_TO_KEXEC_SIGNING]	= "kexec sig",
	[KEY_RESTRICTED_TO_KEY_SIGNING]		= "key sig",
};

/*
 * Provide a part of a description of the key for /proc/keys.
 */
static void public_key_describe(const struct key *asymmetric_key,
				struct seq_file *m)
{
	struct public_key *key = asymmetric_key->payload.data;

	if (key)
		seq_printf(m, "%s.%s",
			   pkey_id_type_name[key->id_type], key->algo->name);
}

/*
 * Describe capabilities/restrictions of the key for /proc/keys.
 */
static void public_key_describe_caps(const struct key *asymmetric_key,
				     struct seq_file *m)
{
	struct public_key *key = asymmetric_key->payload.data;

	if (key)
		seq_puts(m, key_usage_restrictions[key->usage_restriction]);
}

/*
 * Destroy a public key algorithm key.
 */
void public_key_destroy(void *payload)
{
	struct public_key *key = payload;
	int i;

	if (key) {
		for (i = 0; i < ARRAY_SIZE(key->mpi); i++)
			mpi_free(key->mpi[i]);
		kfree(key);
	}
}
EXPORT_SYMBOL_GPL(public_key_destroy);

/*
 * Apply key usage policy.
 */
static int public_key_usage_policy(enum key_being_used_for usage,
				   enum key_usage_restriction restriction)
{
	switch (usage) {
	case KEY_VERIFYING_MODULE_SIGNATURE:
		if (restriction != KEY_RESTRICTED_TO_MODULE_SIGNING &&
		    restriction != KEY_USAGE_NOT_SPECIFIED)
			goto wrong_purpose;
		return 0;
	case KEY_VERIFYING_FIRMWARE_SIGNATURE:
		if (restriction != KEY_RESTRICTED_TO_FIRMWARE_SIGNING) {
			pr_warn("Firmware signed with non-firmware key (%s)\n",
				key_usage_restrictions[restriction]);
			return -EKEYREJECTED;
		}
		return 0;
	case KEY_VERIFYING_KEXEC_SIGNATURE:
		if (restriction != KEY_RESTRICTED_TO_KEXEC_SIGNING &&
		    restriction != KEY_USAGE_NOT_SPECIFIED)
			goto wrong_purpose;
		return 0;
	case KEY_VERIFYING_KEY_SIGNATURE:
		if (restriction != KEY_RESTRICTED_TO_KEY_SIGNING &&
		    restriction != KEY_USAGE_NOT_SPECIFIED)
			goto wrong_purpose;
		return 0;
	case KEY_VERIFYING_KEY_SELF_SIGNATURE:
		return 0;
	default:
		BUG();
	}

wrong_purpose:
	pr_warn("Restricted usage key (%s) used for wrong purpose (%s)\n",
		key_usage_restrictions[restriction],
		key_being_used_for[usage]);
	return -EKEYREJECTED;
}

/*
 * Verify a signature using a public key.
 */
int public_key_verify_signature(const struct public_key *pk,
				const struct public_key_signature *sig,
				enum key_being_used_for usage)
{
	const struct public_key_algorithm *algo;
	int ret;

	BUG_ON(!pk);
	BUG_ON(!pk->mpi[0]);
	BUG_ON(!pk->mpi[1]);
	BUG_ON(!sig);
	BUG_ON(!sig->digest);
	BUG_ON(!sig->mpi[0]);

	algo = pk->algo;
	if (!algo) {
		if (pk->pkey_algo >= PKEY_ALGO__LAST)
			return -ENOPKG;
		algo = pkey_algo[pk->pkey_algo];
		if (!algo)
			return -ENOPKG;
	}

	if (!algo->verify_signature)
		return -ENOTSUPP;

	if (sig->nr_mpi != algo->n_sig_mpi) {
		pr_debug("Signature has %u MPI not %u\n",
			 sig->nr_mpi, algo->n_sig_mpi);
		return -EINVAL;
	}

	ret = public_key_usage_policy(usage, pk->usage_restriction);
	if (ret < 0)
		return ret;

	return algo->verify_signature(pk, sig);
}
EXPORT_SYMBOL_GPL(public_key_verify_signature);

static int public_key_verify_signature_2(const struct key *key,
					 const struct public_key_signature *sig,
					 enum key_being_used_for usage)
{
	const struct public_key *pk = key->payload.data;
	return public_key_verify_signature(pk, sig, usage);
}

/*
 * Public key algorithm asymmetric key subtype
 */
struct asymmetric_key_subtype public_key_subtype = {
	.owner			= THIS_MODULE,
	.name			= "public_key",
	.name_len		= sizeof("public_key") - 1,
	.describe		= public_key_describe,
	.describe_caps		= public_key_describe_caps,
	.destroy		= public_key_destroy,
	.verify_signature	= public_key_verify_signature_2,
};
EXPORT_SYMBOL_GPL(public_key_subtype);
