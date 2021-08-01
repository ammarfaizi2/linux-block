// SPDX-License-Identifier: GPL-2.0
/*
 * The driver-specific portions of the driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 * Copyright (c) 2012-2019 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (c) 2012-2019 Linux Foundation
 *
 * See Documentation/driver-api/driver-model/ for more information.
 */

#ifndef _DEVICE_DRIVER_H_
#define _DEVICE_DRIVER_H_

#include <linux/kmod.h>
#include <linux/kobject.h>
#include <linux/klist.h>
#include <linux/pm.h>
#include <linux/device/bus.h>
#include <linux/module.h>

#include <linux/device_types.h>

extern int __must_check driver_register(struct device_driver *drv);
extern void driver_unregister(struct device_driver *drv);

extern struct device_driver *driver_find(const char *name,
					 struct bus_type *bus);
extern int driver_probe_done(void);
extern void wait_for_device_probe(void);

/* sysfs interface for exporting driver attributes */

struct driver_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device_driver *driver, char *buf);
	ssize_t (*store)(struct device_driver *driver, const char *buf,
			 size_t count);
};

#define DRIVER_ATTR_RW(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_RW(_name)
#define DRIVER_ATTR_RO(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_RO(_name)
#define DRIVER_ATTR_WO(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_WO(_name)

extern int __must_check driver_create_file(struct device_driver *driver,
					const struct driver_attribute *attr);
extern void driver_remove_file(struct device_driver *driver,
			       const struct driver_attribute *attr);

extern int __must_check driver_for_each_device(struct device_driver *drv,
					       struct device *start,
					       void *data,
					       int (*fn)(struct device *dev,
							 void *));
struct device *driver_find_device(struct device_driver *drv,
				  struct device *start, const void *data,
				  int (*match)(struct device *dev, const void *data));

/**
 * driver_find_device_by_name - device iterator for locating a particular device
 * of a specific name.
 * @drv: the driver we're iterating
 * @name: name of the device to match
 */
static inline struct device *driver_find_device_by_name(struct device_driver *drv,
							const char *name)
{
	return driver_find_device(drv, NULL, name, device_match_name);
}

/**
 * driver_find_device_by_of_node- device iterator for locating a particular device
 * by of_node pointer.
 * @drv: the driver we're iterating
 * @np: of_node pointer to match.
 */
static inline struct device *
driver_find_device_by_of_node(struct device_driver *drv,
			      const struct device_node *np)
{
	return driver_find_device(drv, NULL, np, device_match_of_node);
}

/**
 * driver_find_device_by_fwnode- device iterator for locating a particular device
 * by fwnode pointer.
 * @drv: the driver we're iterating
 * @fwnode: fwnode pointer to match.
 */
static inline struct device *
driver_find_device_by_fwnode(struct device_driver *drv,
			     const struct fwnode_handle *fwnode)
{
	return driver_find_device(drv, NULL, fwnode, device_match_fwnode);
}

/**
 * driver_find_device_by_devt- device iterator for locating a particular device
 * by devt.
 * @drv: the driver we're iterating
 * @devt: devt pointer to match.
 */
static inline struct device *driver_find_device_by_devt(struct device_driver *drv,
							dev_t devt)
{
	return driver_find_device(drv, NULL, &devt, device_match_devt);
}

static inline struct device *driver_find_next_device(struct device_driver *drv,
						     struct device *start)
{
	return driver_find_device(drv, start, NULL, device_match_any);
}

#ifdef CONFIG_ACPI
/**
 * driver_find_device_by_acpi_dev : device iterator for locating a particular
 * device matching the ACPI_COMPANION device.
 * @drv: the driver we're iterating
 * @adev: ACPI_COMPANION device to match.
 */
static inline struct device *
driver_find_device_by_acpi_dev(struct device_driver *drv,
			       const struct acpi_device *adev)
{
	return driver_find_device(drv, NULL, adev, device_match_acpi_dev);
}
#else
static inline struct device *
driver_find_device_by_acpi_dev(struct device_driver *drv, const void *adev)
{
	return NULL;
}
#endif

extern int driver_deferred_probe_timeout;
void driver_deferred_probe_add(struct device *dev);
int driver_deferred_probe_check_state(struct device *dev);
void driver_init(void);

/**
 * module_driver() - Helper macro for drivers that don't do anything
 * special in module init/exit. This eliminates a lot of boilerplate.
 * Each module may only use this macro once, and calling it replaces
 * module_init() and module_exit().
 *
 * @__driver: driver name
 * @__register: register function for this driver type
 * @__unregister: unregister function for this driver type
 * @...: Additional arguments to be passed to __register and __unregister.
 *
 * Use this macro to construct bus specific macros for registering
 * drivers, and do not use it on its own.
 */
#define module_driver(__driver, __register, __unregister, ...) \
static int __init __driver##_init(void) \
{ \
	return __register(&(__driver) , ##__VA_ARGS__); \
} \
module_init(__driver##_init); \
static void __exit __driver##_exit(void) \
{ \
	__unregister(&(__driver) , ##__VA_ARGS__); \
} \
module_exit(__driver##_exit);

/**
 * builtin_driver() - Helper macro for drivers that don't do anything
 * special in init and have no exit. This eliminates some boilerplate.
 * Each driver may only use this macro once, and calling it replaces
 * device_initcall (or in some cases, the legacy __initcall).  This is
 * meant to be a direct parallel of module_driver() above but without
 * the __exit stuff that is not used for builtin cases.
 *
 * @__driver: driver name
 * @__register: register function for this driver type
 * @...: Additional arguments to be passed to __register
 *
 * Use this macro to construct bus specific macros for registering
 * drivers, and do not use it on its own.
 */
#define builtin_driver(__driver, __register, ...) \
static int __init __driver##_init(void) \
{ \
	return __register(&(__driver) , ##__VA_ARGS__); \
} \
device_initcall(__driver##_init);

#endif	/* _DEVICE_DRIVER_H_ */
