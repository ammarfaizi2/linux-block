/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_OF_TYPES_H
#define _LINUX_OF_TYPES_H

/*
 * Definitions for talking to the Open Firmware PROM on
 * Power Macintosh and other computers.
 *
 * Copyright (C) 1996-2005 Paul Mackerras.
 *
 * Updates for PPC64 by Peter Bergner & David Engebretsen, IBM Corp.
 * Updates for SPARC64 by David S. Miller
 * Derived from PowerPC and Sparc prom.h files by Stephen Rothwell, IBM Corp.
 */
#include <linux/fwnode.h>
#include <linux/sysfs_types.h>
#include <linux/kobject_types.h>

typedef u32 phandle;
typedef u32 ihandle;

struct property {
	char	*name;
	int	length;
	void	*value;
	struct property *next;
#if defined(CONFIG_OF_DYNAMIC) || defined(CONFIG_SPARC)
	unsigned long _flags;
#endif
#if defined(CONFIG_OF_PROMTREE)
	unsigned int unique_id;
#endif
#if defined(CONFIG_OF_KOBJ)
	struct bin_attribute attr;
#endif
};

#if defined(CONFIG_SPARC)
struct of_irq_controller;
#endif

struct device_node {
	const char *name;
	phandle phandle;
	const char *full_name;
	struct fwnode_handle fwnode;

	struct	property *properties;
	struct	property *deadprops;	/* removed properties */
	struct	device_node *parent;
	struct	device_node *child;
	struct	device_node *sibling;
#if defined(CONFIG_OF_KOBJ)
	struct	kobject kobj;
#endif
	unsigned long _flags;
	void	*data;
#if defined(CONFIG_SPARC)
	unsigned int unique_id;
	struct of_irq_controller *irq_trans;
#endif
};

#define MAX_PHANDLE_ARGS 16
struct of_phandle_args {
	struct device_node *np;
	int args_count;
	uint32_t args[MAX_PHANDLE_ARGS];
};

struct of_phandle_iterator {
	/* Common iterator information */
	const char *cells_name;
	int cell_count;
	const struct device_node *parent;

	/* List size information */
	const __be32 *list_end;
	const __be32 *phandle_end;

	/* Current position state */
	const __be32 *cur;
	uint32_t cur_count;
	phandle phandle;
	struct device_node *node;
};

struct of_reconfig_data {
	struct device_node	*dn;
	struct property		*prop;
	struct property		*old_prop;
};

/*
 * struct device_node flag descriptions
 * (need to be visible even when !CONFIG_OF)
 */
#define OF_DYNAMIC		1 /* (and properties) allocated via kmalloc */
#define OF_DETACHED		2 /* detached from the device tree */
#define OF_POPULATED		3 /* device already created */
#define OF_POPULATED_BUS	4 /* platform bus created for children */
#define OF_OVERLAY		5 /* allocated for an overlay */
#define OF_OVERLAY_FREE_CSET	6 /* in overlay cset being freed */

#define OF_BAD_ADDR	((u64)-1)

#endif /* _LINUX_OF_TYPES_H */
