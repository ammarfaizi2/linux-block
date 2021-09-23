// SPDX-License-Identifier: GPL-2.0
/*
 * device.h - generic, centralized driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 *
 * See Documentation/driver-api/driver-model/ for more information.
 */

#ifndef _DEVICE_API_H_
#define _DEVICE_API_H_

#include <linux/device_types.h>
#include <linux/device_api_lock.h>

#include <linux/dev_printk.h>
#include <linux/ioport.h>
#include <linux/kobject_api.h>
#include <linux/klist.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/mutex_api.h>
#include <linux/pm.h>
#include <linux/atomic.h>
#include <linux/uidgid.h>
#include <linux/gfp.h>
#include <linux/overflow.h>
#include <linux/device/bus.h>
#include <linux/device/class.h>
#include <linux/device/driver.h>
#include <linux/numa_types.h>

#include <asm/device.h>

struct device;
struct device_private;
struct device_driver;
struct driver_private;
struct module;
struct class;
struct subsys_private;
struct device_node;
struct fwnode_handle;
struct iommu_ops;
struct iommu_group;
struct dev_pin_info;
struct dev_iommu;

/**
 * struct subsys_interface - interfaces to device functions
 * @name:       name of the device function
 * @subsys:     subsystem of the devices to attach to
 * @node:       the list of functions registered at the subsystem
 * @add_dev:    device hookup to device function handler
 * @remove_dev: device hookup to device function handler
 *
 * Simple interfaces attached to a subsystem. Multiple interfaces can
 * attach to a subsystem and its devices. Unlike drivers, they do not
 * exclusively claim or control devices. Interfaces usually represent
 * a specific functionality of a subsystem/class of devices.
 */
struct subsys_interface {
	const char *name;
	struct bus_type *subsys;
	struct list_head node;
	int (*add_dev)(struct device *dev, struct subsys_interface *sif);
	void (*remove_dev)(struct device *dev, struct subsys_interface *sif);
};

int subsys_interface_register(struct subsys_interface *sif);
void subsys_interface_unregister(struct subsys_interface *sif);

int subsys_system_register(struct bus_type *subsys,
			   const struct attribute_group **groups);
int subsys_virtual_register(struct bus_type *subsys,
			    const struct attribute_group **groups);

ssize_t device_show_ulong(struct device *dev, struct device_attribute *attr,
			  char *buf);
ssize_t device_store_ulong(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count);
ssize_t device_show_int(struct device *dev, struct device_attribute *attr,
			char *buf);
ssize_t device_store_int(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count);
ssize_t device_show_bool(struct device *dev, struct device_attribute *attr,
			char *buf);
ssize_t device_store_bool(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count);

/**
 * devm_alloc_percpu - Resource-managed alloc_percpu
 * @dev: Device to allocate per-cpu memory for
 * @type: Type to allocate per-cpu memory for
 *
 * Managed alloc_percpu. Per-cpu memory allocated with this function is
 * automatically freed on driver detach.
 *
 * RETURNS:
 * Pointer to allocated memory on success, NULL on failure.
 */
#define devm_alloc_percpu(dev, type)      \
	((typeof(type) __percpu *)__devm_alloc_percpu((dev), sizeof(type), \
						      __alignof__(type)))

void __percpu *__devm_alloc_percpu(struct device *dev, size_t size,
				   size_t align);
void devm_free_percpu(struct device *dev, void __percpu *pdata);

/**
 * struct device_link - Device link representation.
 * @supplier: The device on the supplier end of the link.
 * @s_node: Hook to the supplier device's list of links to consumers.
 * @consumer: The device on the consumer end of the link.
 * @c_node: Hook to the consumer device's list of links to suppliers.
 * @link_dev: device used to expose link details in sysfs
 * @status: The state of the link (with respect to the presence of drivers).
 * @flags: Link flags.
 * @rpm_active: Whether or not the consumer device is runtime-PM-active.
 * @kref: Count repeated addition of the same link.
 * @rm_work: Work structure used for removing the link.
 * @supplier_preactivated: Supplier has been made active before consumer probe.
 */
struct device_link {
	struct device *supplier;
	struct list_head s_node;
	struct device *consumer;
	struct list_head c_node;
	struct device link_dev;
	enum device_link_state status;
	u32 flags;
	refcount_t rpm_active;
	struct kref kref;
	struct work_struct rm_work;
	bool supplier_preactivated; /* Owned by consumer probe. */
};

/**
 * device_iommu_mapped - Returns true when the device DMA is translated
 *			 by an IOMMU
 * @dev: Device to perform the check on
 */
static inline bool device_iommu_mapped(struct device *dev)
{
	return (dev->iommu_group != NULL);
}

/* Get the wakeup routines, which depend on struct device */
#include <linux/pm_wakeup.h>

/**
 * dev_bus_name - Return a device's bus/class name, if at all possible
 * @dev: struct device to get the bus/class name of
 *
 * Will return the name of the bus/class the device is attached to.  If it is
 * not attached to a bus/class, an empty string will be returned.
 */
static inline const char *dev_bus_name(const struct device *dev)
{
	return dev->bus ? dev->bus->name : (dev->class ? dev->class->name : "");
}

static inline struct irq_domain *dev_get_msi_domain(const struct device *dev)
{
#ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
	return dev->msi.domain;
#else
	return NULL;
#endif
}

static inline void dev_set_msi_domain(struct device *dev, struct irq_domain *d)
{
#ifdef CONFIG_GENERIC_MSI_IRQ_DOMAIN
	dev->msi.domain = d;
#endif
}

static inline struct pm_subsys_data *dev_to_psd(struct device *dev)
{
	return dev ? dev->power.subsys_data : NULL;
}

static inline unsigned int dev_get_uevent_suppress(const struct device *dev)
{
	return dev->kobj.uevent_suppress;
}

static inline void dev_set_uevent_suppress(struct device *dev, int val)
{
	dev->kobj.uevent_suppress = val;
}

static inline int device_is_registered(struct device *dev)
{
	return dev->kobj.state_in_sysfs;
}

static inline void device_enable_async_suspend(struct device *dev)
{
	if (!dev->power.is_prepared)
		dev->power.async_suspend = true;
}

static inline void device_disable_async_suspend(struct device *dev)
{
	if (!dev->power.is_prepared)
		dev->power.async_suspend = false;
}

static inline bool device_async_suspend_enabled(struct device *dev)
{
	return !!dev->power.async_suspend;
}

static inline bool device_pm_not_required(struct device *dev)
{
	return dev->power.no_pm;
}

static inline void device_set_pm_not_required(struct device *dev)
{
	dev->power.no_pm = true;
}

static inline void dev_pm_syscore_device(struct device *dev, bool val)
{
#ifdef CONFIG_PM_SLEEP
	dev->power.syscore = val;
#endif
}

static inline void dev_pm_set_driver_flags(struct device *dev, u32 flags)
{
	dev->power.driver_flags = flags;
}

static inline bool dev_pm_test_driver_flags(struct device *dev, u32 flags)
{
	return !!(dev->power.driver_flags & flags);
}

static inline bool dev_has_sync_state(struct device *dev)
{
	if (!dev)
		return false;
	if (dev->driver && dev->driver->sync_state)
		return true;
	if (dev->bus && dev->bus->sync_state)
		return true;
	return false;
}

static inline void dev_set_removable(struct device *dev,
				     enum device_removable removable)
{
	dev->removable = removable;
}

static inline bool dev_is_removable(struct device *dev)
{
	return dev->removable == DEVICE_REMOVABLE;
}

static inline bool dev_removable_is_valid(struct device *dev)
{
	return dev->removable != DEVICE_REMOVABLE_NOT_SUPPORTED;
}

static inline bool device_supports_offline(struct device *dev)
{
	return dev->bus && dev->bus->offline && dev->bus->online;
}

static inline int dev_num_vf(struct device *dev)
{
	if (dev->bus && dev->bus->num_vf)
		return dev->bus->num_vf(dev);
	return 0;
}

/*
 * Root device objects for grouping under /sys/devices
 */
struct device *__root_device_register(const char *name, struct module *owner);

/* This is a macro to avoid include problems with THIS_MODULE */
#define root_device_register(name) \
	__root_device_register(name, THIS_MODULE)

void root_device_unregister(struct device *root);

/*
 * Manual binding of a device to driver. See drivers/base/bus.c
 * for information on use.
 */
int __must_check device_driver_attach(struct device_driver *drv,
				      struct device *dev);
int __must_check device_bind_driver(struct device *dev);
void device_release_driver(struct device *dev);
int  __must_check device_attach(struct device *dev);
int __must_check driver_attach(struct device_driver *drv);
void device_initial_probe(struct device *dev);
int __must_check device_reprobe(struct device *dev);

bool device_is_bound(struct device *dev);

/*
 * Platform "fixup" functions - allow the platform to have their say
 * about devices and actions that the general device layer doesn't
 * know about.
 */
/* Notify platform of device discovery */
extern int (*platform_notify)(struct device *dev);

extern int (*platform_notify_remove)(struct device *dev);


bool kill_device(struct device *dev);

#ifdef CONFIG_DEVTMPFS
int devtmpfs_mount(void);
#else
static inline int devtmpfs_mount(void) { return 0; }
#endif

/* drivers/base/power/shutdown.c */
void device_shutdown(void);

/* Device links interface. */
struct device_link *device_link_add(struct device *consumer,
				    struct device *supplier, u32 flags);
void device_link_del(struct device_link *link);
void device_link_remove(void *consumer, struct device *supplier);
void device_links_supplier_sync_state_pause(void);
void device_links_supplier_sync_state_resume(void);

/* Create alias, so I can be autoloaded. */
#define MODULE_ALIAS_CHARDEV(major,minor) \
	MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major) \
	MODULE_ALIAS("char-major-" __stringify(major) "-*")

#ifdef CONFIG_SYSFS_DEPRECATED
extern long sysfs_deprecated;
#else
#define sysfs_deprecated 0
#endif

#endif /* _DEVICE_API_H_ */
