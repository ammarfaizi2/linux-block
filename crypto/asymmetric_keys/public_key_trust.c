/* Instantiate a public key crypto key from an X.509 Certificate
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "X.509: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/mpi.h>
#include <linux/asn1_decoder.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include <keys/system_keyring.h>
#include <crypto/hash.h>
#include "asymmetric_keys.h"
#include "public_key.h"
#include "x509_parser.h"

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
 * x509_request_asymmetric_key - Request a key by X.509 certificate params.
 * @keyring: The keys to search.
 * @id: The issuer & serialNumber to look for or NULL.
 * @skid: The subjectKeyIdentifier to look for or NULL.
 * @partial: Use partial match if true, exact if false.
 *
 * Find a key in the given keyring by identifier.  The preferred identifier is
 * the issuer + serialNumber and the fallback identifier is the
 * subjectKeyIdentifier.  If both are given, the lookup is by the former, but
 * the latter must also match.
 */
struct key *x509_request_asymmetric_key(struct key *keyring,
					const struct asymmetric_key_id *id,
					const struct asymmetric_key_id *skid,
					bool partial)
{
	struct key *key;
	key_ref_t ref;
	const char *lookup;
	char *req, *p;
	int len;

	if (id) {
		lookup = id->data;
		len = id->len;
	} else {
		lookup = skid->data;
		len = skid->len;
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
	if (id && skid) {
		const struct asymmetric_key_ids *kids = asymmetric_key_ids(key);
		if (!kids->id[1]) {
			pr_debug("issuer+serial match, but expected SKID missing\n");
			goto reject;
		}
		if (!asymmetric_key_id_same(skid, kids->id[1])) {
			pr_debug("issuer+serial match, but SKID does not\n");
			goto reject;
		}
	}

	pr_devel("<==%s() = 0 [%x]\n", __func__, key_serial(key));
	return key;

reject:
	key_put(key);
	return ERR_PTR(-EKEYREJECTED);
}
EXPORT_SYMBOL_GPL(x509_request_asymmetric_key);

/*
 * Check the new certificate against the ones in the trust keyring.  If one of
 * those is the signing key and validates the new certificate, then mark the
 * new certificate as being trusted.
 *
 * Return 0 if the new certificate was successfully validated, 1 if we couldn't
 * find a matching parent certificate in the trusted list and an error if there
 * is a matching certificate but the signature check fails.
 */
int x509_validate_trust(struct x509_certificate *cert,
			struct key *trust_keyring)
{
	struct public_key_signature *sig = cert->sig;
	struct key *key;
	int ret = 1;

	if (!trust_keyring)
		return -EOPNOTSUPP;
	if (ca_keyid && !asymmetric_key_id_partial(sig->auth_ids[1], ca_keyid))
		return -EPERM;
	if (cert->unsupported_sig)
		return -ENOPKG;

	key = x509_request_asymmetric_key(trust_keyring,
					  sig->auth_ids[0], sig->auth_ids[1],
					  false);
	if (IS_ERR(key))
		return PTR_ERR(key);

	if (!use_builtin_keys ||
	    test_bit(KEY_FLAG_BUILTIN, &key->flags)) {
		ret = public_key_verify_signature(
			key->payload.data[asym_crypto], cert->sig);
		if (ret == -ENOPKG)
			cert->unsupported_sig = true;
	}
	key_put(key);
	return ret;
}
