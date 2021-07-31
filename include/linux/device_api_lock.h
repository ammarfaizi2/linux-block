// SPDX-License-Identifier: GPL-2.0
#ifndef _DEVICE_API_LOCK_H_
#define _DEVICE_API_LOCK_H_

#include <linux/device_api.h>

#include <linux/lockdep_api.h>
#include <linux/mutex_api.h>

static inline void device_lock(struct device *dev)
{
	mutex_lock(&dev->mutex);
}

static inline int device_lock_interruptible(struct device *dev)
{
	return mutex_lock_interruptible(&dev->mutex);
}

static inline int device_trylock(struct device *dev)
{
	return mutex_trylock(&dev->mutex);
}

static inline void device_unlock(struct device *dev)
{
	mutex_unlock(&dev->mutex);
}

static inline void device_lock_assert(struct device *dev)
{
	lockdep_assert_held(&dev->mutex);
}

#endif /* _DEVICE_API_LOCK_H_ */
