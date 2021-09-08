/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015, Intel Corporation
 * Author: Jiang Liu <jiang.liu@linux.intel.com>
 */
#ifndef _LINUX_RESOURCE_EXT_TYPES_H
#define _LINUX_RESOURCE_EXT_TYPES_H

#include <linux/ioport.h>

/* Represent resource window for bridge devices */
struct resource_win {
	struct resource res;		/* In master (CPU) address space */
	resource_size_t offset;		/* Translation offset for bridge */
};

/*
 * Common resource list management data structure and interfaces to support
 * ACPI, PNP and PCI host bridge etc.
 */
struct resource_entry {
	struct list_head	node;
	struct resource		*res;	/* In master (CPU) address space */
	resource_size_t		offset;	/* Translation offset for bridge */
	struct resource		__res;	/* Default storage for res */
};

#endif /* _LINUX_RESOURCE_EXT_TYPES_H */
