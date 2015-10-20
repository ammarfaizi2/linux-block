/* Validate one public key against another to determine trust chaining.
 *
 * Copyright (C) 2015 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKEY: "fmt
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include "asymmetric_keys.h"
#include "public_key.h"

static bool use_builtin_keys;
static struct asymmetric_key_id *ca_keyid;

#ifndef MODULE
static struct {
	struct asymmetric_key_id id;
	unsigned char data[10];
} cakey;

static int __init ca_keys_setup(char *str)
{
	if (!str)		/* default system keyring */
		return 1;

	if (strncmp(str, "id:", 3) == 0) {
		struct asymmetric_key_id *p = &cakey.id;
		size_t hexlen = (strlen(str) - 3) / 2;
		int ret;

		if (hexlen == 0 || hexlen > sizeof(cakey.data)) {
			pr_err("Missing or invalid ca_keys id\n");
			return 1;
		}

		ret = __asymmetric_key_hex_to_key_id(str + 3, p, hexlen);
		if (ret < 0)
			pr_err("Unparsable ca_keys id hex string\n");
		else
			ca_keyid = p;	/* owner key 'id:xxxxxx' */
	} else if (strcmp(str, "builtin") == 0) {
		use_builtin_keys = true;
	}

	return 1;
}
__setup("ca_keys=", ca_keys_setup);
#endif

/**
 * request_asymmetric_key - Request a key by ID.
 * @keyring: The keys to search.
 * @id_0: The first ID to look for or NULL.
 * @id_1: The second ID to look for or NULL.
 * @partial: Use partial match if true, exact if false.
 *
 * Find a key in the given keyring by identifier.  The preferred identifier is
 * the id_0 and the fallback identifier is the id_1.  If both are given, the
 * lookup is by the former, but the latter must also match.
 */
struct key *request_asymmetric_key(struct key *keyring,
				   const struct asymmetric_key_id *id_0,
				   const struct asymmetric_key_id *id_1,
				   bool partial)
{
	struct key *key;
	key_ref_t ref;
	const char *lookup;
	char *req, *p;
	int len;

	if (id_0) {
		lookup = id_0->data;
		len = id_0->len;
	} else {
		lookup = id_1->data;
		len = id_1->len;
	}

	/* Construct an identifier "id:<keyid>". */
	p = req = kmalloc(2 + 1 + len * 2 + 1, GFP_KERNEL);
	if (!req)
		return ERR_PTR(-ENOMEM);

	if (partial) {
		*p++ = 'i';
		*p++ = 'd';
	} else {
		*p++ = 'e';
		*p++ = 'x';
	}
	*p++ = ':';
	p = bin2hex(p, lookup, len);
	*p = 0;

	pr_debug("Look up: \"%s\"\n", req);

	ref = keyring_search(make_key_ref(keyring, 1),
			     &key_type_asymmetric, req);
	if (IS_ERR(ref))
		pr_debug("Request for key '%s' err %ld\n", req, PTR_ERR(ref));
	kfree(req);

	if (IS_ERR(ref)) {
		switch (PTR_ERR(ref)) {
			/* Hide some search errors */
		case -EACCES:
		case -ENOTDIR:
		case -EAGAIN:
			return ERR_PTR(-ENOKEY);
		default:
			return ERR_CAST(ref);
		}
	}

	key = key_ref_to_ptr(ref);
	if (id_0 && id_1) {
		const struct asymmetric_key_ids *kids = asymmetric_key_ids(key);

		if (!kids->id[0]) {
			pr_debug("First ID matches, but second is missing\n");
			goto reject;
		}
		if (!asymmetric_key_id_same(id_1, kids->id[1])) {
			pr_debug("First ID matches, but second does not\n");
			goto reject;
		}
	}

	pr_devel("<==%s() = 0 [%x]\n", __func__, key_serial(key));
	return key;

reject:
	key_put(key);
	return ERR_PTR(-EKEYREJECTED);
}
EXPORT_SYMBOL_GPL(request_asymmetric_key);

/*
 * Check the new certificate against the ones in the trust keyring.  If one of
 * those is the signing key and validates the new certificate, then mark the
 * new certificate as being trusted.
 *
 * Return 0 if the new certificate was successfully validated, -ENOKEY if we
 * couldn't find a matching parent certificate in the trusted list and some
 * other error if there is a matching certificate but the signature check
 * fails or cannot be performed.
 */
int public_key_validate_trust(const struct public_key_signature *sig,
			      struct key *trust_keyring)
{
	struct key *key;
	int ret;

	if (!trust_keyring)
		return -EOPNOTSUPP;
	if (ca_keyid && !asymmetric_key_id_partial(sig->auth_ids[1], ca_keyid))
		return -EPERM;

	key = request_asymmetric_key(trust_keyring,
				     sig->auth_ids[0],
				     sig->auth_ids[1],
				     false);
	if (IS_ERR(key))
		return -ENOKEY;

	if (use_builtin_keys && !test_bit(KEY_FLAG_BUILTIN, &key->flags))
		ret = -ENOKEY;
	else
		ret = verify_signature(key, sig);
	key_put(key);
	return ret;
}
