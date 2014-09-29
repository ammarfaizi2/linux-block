/* TPM-based public key algorithm internals
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

struct tpm_asymmetric_key {
	struct tpm_wrapped_key *wrapped_key;
	u32	parent_tpm_handle;
	u8	parent_authdata[TPM_DIGEST_SIZE];
	u8	key_authdata[TPM_DIGEST_SIZE];
};

extern struct asymmetric_key_subtype tpm_key_subtype;
