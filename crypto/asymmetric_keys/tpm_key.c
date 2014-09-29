/* In-TPM asymmetric public-key crypto subtype
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "TPK: "fmt
#include <linux/module.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/tpm.h>
#include <keys/asymmetric-subtype.h>
#include "tpm_key.h"

MODULE_LICENSE("GPL");

/*
 * Provide a part of a description of the key for /proc/keys.
 */
static void tpm_key_describe(const struct key *asymmetric_key,
			     struct seq_file *m)
{
	struct tpm_asymmetric_key *key = asymmetric_key->payload.data;
	struct tpm_wrapped_key *wrap;

	if (key && key->wrapped_key) {
		wrap = key->wrapped_key;
		seq_printf(m, "TPM.RSA %*phN",
			   wrap->pubkey_len, wrap->data + wrap->pubkey_offset);
	}
}

/*
 * Destroy a TPM-based key.
 */
static void tpm_key_destroy(void *payload)
{
	struct tpm_asymmetric_key *key = payload;

	if (key) {
		kfree(key->wrapped_key);
		kfree(key);
		tpm_library_unuse();
	}
}

/*
 * Verify a signature using a TPM-based key.
 */
static int tpm_key_verify_signature(const struct key *key,
				    const struct public_key_signature *sig)
{
	return -EOPNOTSUPP;
}

/*
 * Public key algorithm asymmetric key subtype
 */
struct asymmetric_key_subtype tpm_key_subtype = {
	.owner			= THIS_MODULE,
	.name			= "tpm_key",
	.describe		= tpm_key_describe,
	.destroy		= tpm_key_destroy,
	.verify_signature	= tpm_key_verify_signature,
};
EXPORT_SYMBOL_GPL(tpm_key_subtype);
