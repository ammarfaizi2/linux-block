// SPDX-License-Identifier: GPL-2.0-or-later
/* Data for Kerberos library self-testing
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "internal.h"

/*
 * Pseudo-random function tests.
 */
const struct krb5_prf_test krb5_prf_tests[] = {
	{/* END */}
};

/*
 * Key derivation tests.
 */
const struct krb5_key_test krb5_key_tests[] = {
	{/* END */}
};

/*
 * Encryption tests.
 */
const struct krb5_enc_test krb5_enc_tests[] = {
	{/* END */}
};

/*
 * Checksum generation tests.
 */
const struct krb5_mic_test krb5_mic_tests[] = {
	{/* END */}
};
