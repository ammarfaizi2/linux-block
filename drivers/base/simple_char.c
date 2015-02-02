/*
 * A simple way to create character devices
 *
 * Copyright (c) 2015 Andy Lutomirski <luto@amacapital.net>
 *
 * Loosely based, somewhat arbitrarily, on the UIO driver, which is one
 * of many copies of essentially identical boilerplate.
 *
 * Licensed under the GPLv2.
 */

#include <linux/simple_char.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/idr.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/kobject.h>
#include <linux/cdev.h>

#define MAX_MINORS (1U << MINORBITS)

struct simple_char_major {
	struct cdev cdev;
	unsigned majornum;
	struct idr idr;
	struct mutex lock;
};

static struct simple_char_major *fully_dynamic_major;
static DEFINE_MUTEX(fully_dynamic_major_lock);

static int simple_char_open(struct inode *inode, struct file *filep)
{
	struct simple_char_major *major =
		container_of(inode->i_cdev, struct simple_char_major,
			     cdev);
	void *private;
	const struct simple_char_ops *ops;
	int ret = 0;

	mutex_lock(&major->lock);

	{
		/*
		 * This is a separate block to make the locking entirely
		 * clear.  The only thing keeping minor alive is major->lock.
		 * We need to be completely done with the simple_char_minor
		 * by the time we release the lock.
		 */
		struct simple_char_minor *minor;
		minor = idr_find(&major->idr, iminor(inode));
		if (!minor || !minor->ops->reference(minor->private)) {
			mutex_unlock(&major->lock);
			return -ENODEV;
		}
		private = minor->private;
		ops = minor->ops;
	}

	mutex_unlock(&major->lock);

	replace_fops(filep, ops->fops);
	filep->private_data = private;
	if (ops->fops->open)
		ret = ops->fops->open(inode, filep);

	return ret;
}

static const struct file_operations simple_char_fops = {
	.open = simple_char_open,
	.llseek = noop_llseek,
};

struct simple_char_major *simple_char_major_create(const char *name)
{
	struct simple_char_major *major = NULL;
	dev_t devt;
	int ret;

	ret = alloc_chrdev_region(&devt, 0, MAX_MINORS, name);
	if (ret)
		goto out;

	ret = -ENOMEM;
	major = kmalloc(sizeof(struct simple_char_major), GFP_KERNEL);
	if (!major)
		goto out_unregister;
	cdev_init(&major->cdev, &simple_char_fops);
	kobject_set_name(&major->cdev.kobj, "%s", name);

	ret = cdev_add(&major->cdev, devt, MAX_MINORS);
	if (ret)
		goto out_free;

	major->majornum = MAJOR(devt);
	idr_init(&major->idr);
	return major;

out_free:
	cdev_del(&major->cdev);
	kfree(major);
out_unregister:
	unregister_chrdev_region(devt, MAX_MINORS);
out:
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(simple_char_major_create);

void simple_char_major_free(struct simple_char_major *major)
{
	BUG_ON(!idr_is_empty(&major->idr));

	cdev_del(&major->cdev);
	unregister_chrdev_region(MKDEV(major->majornum, 0), MAX_MINORS);
	idr_destroy(&major->idr);
	kfree(major);
}

static struct simple_char_major *get_fully_dynamic_major(void)
{
	struct simple_char_major *major =
		smp_load_acquire(&fully_dynamic_major);
	if (major)
		return major;

	mutex_lock(&fully_dynamic_major_lock);

	if (fully_dynamic_major) {
		major = fully_dynamic_major;
		goto out;
	}

	major = simple_char_major_create("fully_dynamic");
	if (!IS_ERR(major))
		smp_store_release(&fully_dynamic_major, major);

out:
	mutex_unlock(&fully_dynamic_major_lock);
	return major;
	
}

/**
 * simple_char_minor_create() - create a chardev minor
 * @major:	Major to use or NULL for a fully dynamic chardev.
 * @ops:	simple_char_ops to associate with the minor.
 * @private:	opaque pointer for @ops's use.
 *
 * simple_char_minor_create() creates a minor chardev.  For new code,
 * @major should be NULL; this will create a minor chardev with fully
 * dynamic major and minor numbers and without a useful name in
 * /proc/devices.  (All recent user code should be using sysfs
 * exclusively to map between devices and device numbers.)  For legacy
 * code, @major can come from simple_char_major_create().
 *
 * The chardev will use @ops->fops for its file operations.  Before any
 * of those operations are called, the struct file's private_data will
 * be set to @private.
 *
 * To simplify reference counting, @ops->reference will be called before
 * @ops->fops->open.  @ops->reference should take any needed references
 * and return true if the object being opened still exists, and it
 * should return false without taking references if the object is dying.
 * @ops->reference is called with locks held, so it should neither sleep
 * nor take heavy locks.
 *
 * @ops->fops->release (and @ops->fops->open, if it exists and fails)
 * are responsible for releasing any references takes by @ops->reference.
 *
 * The minor must be destroyed by @simple_char_minor_free.  After
 * @simple_char_minor_free returns, @ops->reference will not be called.
 */
struct simple_char_minor *
simple_char_minor_create(struct simple_char_major *major,
			 const struct simple_char_ops *ops,
			 void *private)
{
	int ret;
	struct simple_char_minor *minor = NULL;

	if (!major) {
		major = get_fully_dynamic_major();
		if (IS_ERR(major))
			return (void *)major;
	}

	minor = kmalloc(sizeof(struct simple_char_minor), GFP_KERNEL);
	if (!minor)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&major->lock);
	ret = idr_alloc(&major->idr, minor, 0, MAX_MINORS, GFP_KERNEL);
	if (ret >= 0) {
		minor->devt = MKDEV(major->majornum, ret);
		ret = 0;
	}
	/* Warn on ENOSPC?  It's embarrassing if it ever happens. */
	mutex_unlock(&major->lock);

	if (ret) {
		kfree(minor);
		return ERR_PTR(ret);
	}

	minor->major = major;
	minor->private = private;
	minor->ops = ops;
	return minor;
}

/**
 * simple_char_minor_free() - Free a simple_char chardev minor
 * @minor:	the minor to free.
 *
 * This frees a chardev minor and prevents that minor's @ops->reference
 * op from being called in the future.
 */
void simple_char_minor_free(struct simple_char_minor *minor)
{
	mutex_lock(&minor->major->lock);
	idr_remove(&minor->major->idr, MINOR(minor->devt));
	mutex_unlock(&minor->major->lock);
	kfree(minor);
}
EXPORT_SYMBOL(simple_char_minor_free);
