/* SPDX-License-Identifier: GPL-2.0 */
/* Defs for for zerocopy filler fragment allocator.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_ZCOPY_ALLOC_H
#define _LINUX_ZCOPY_ALLOC_H

struct bio_vec;

int zcopy_alloc(size_t size, struct bio_vec *bvec, gfp_t gfp);
int zcopy_memdup(size_t size, const void *p, struct bio_vec *bvec, gfp_t gfp);

#endif /* _LINUX_ZCOPY_ALLOC_H */
