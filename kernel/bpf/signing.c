// SPDX-License-Identifier: GPL-2.0-or-later
/* BPF signature checker
 *
 * Copyright (C) 2020 Red Hat, Inc. All Rights Reserved.
 * Written by Arnaldo Carvalho de Melo (acme@redhat.com).
 *
 * Heavily lifted from:
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/kernel.h>
#include <linux/module_signature.h>
#include <linux/filter.h>
#include <linux/verification.h>
#include <crypto/public_key.h>
#include <linux/bpf.h>

/*
 * Verify the signature for a BPF bytecode.
 */
int bpf_verify_sig(struct bpf_prog *prog, union bpf_attr *attr)
{
	size_t sig_len, bytecode_len = bpf_prog_insn_size(prog);
	void *bytecode = prog->insns, *prog_sig;
	struct module_signature ms;
	int ret;

	pr_devel("==>%s(,%u)\n", __func__, attr->prog_sig_len);

	if (attr->prog_sig_len <= sizeof(ms))
		return -EBADMSG;

	// XXX Couldn't find in the module path where it validates the max 'len' arg...
	prog_sig = kzalloc(attr->prog_sig_len, GFP_KERNEL | GFP_USER);
	if (prog_sig == NULL)
		return -ENOMEM;

	ret = -EFAULT;
	if (copy_from_user(prog_sig, u64_to_user_ptr(attr->prog_sig), attr->prog_sig_len) != 0)
		goto out_free;

	memcpy(&ms, prog_sig + attr->prog_sig_len - sizeof(ms), sizeof(ms));

	ret = bpf_check_sig(&ms, attr->prog_sig_len, prog->aux->name);
	if (ret)
		goto out_free;

	sig_len = be32_to_cpu(ms.sig_len);

	ret = verify_pkcs7_signature(bytecode, bytecode_len, prog_sig, sig_len,
				     VERIFY_USE_SECONDARY_KEYRING,
				     VERIFYING_BPF_SIGNATURE, NULL, NULL);
out_free:
	kfree(prog_sig);
	return ret;
}
