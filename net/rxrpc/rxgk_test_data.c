// SPDX-License-Identifier: GPL-2.0-or-later
/* Data for RxGK self-testing
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ar-internal.h"
#include "rxgk_common.h"

/*
 * Pseudo-random function tests.
 */
const struct rxgk_prf_test rxgk_prf_tests[] = {
	{/* END */}
};

/*
 * Key derivation tests.
 */
const struct rxgk_key_test rxgk_key_tests[] = {
	{/* END */}
};

/*
 * Encryption tests.
 */
const struct rxgk_enc_test rxgk_enc_tests[] = {
	{/* END */}
};

/*
 * Checksum generation tests.
 */
const struct rxgk_mic_test rxgk_mic_tests[] = {
	{/* END */}
};
