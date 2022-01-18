// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple RTKit IPC Library
 * Copyright (C) The Asahi Linux Contributors
 *
 * Apple's SoCs come with various co-processors running their RTKit operating
 * system. This protocol library is used by client drivers to use the
 * features provided by them.
 */
#ifndef _LINUX_APPLE_RTKIT_H_
#define _LINUX_APPLE_RTKIT_H_

#include <linux/device.h>
#include <linux/ioport.h>
#include <linux/types.h>
#include <linux/mailbox_client.h>

/*
 * APPLE_RTKIT_SHMEM_OWNER_LINUX - shared memory buffers are allocated and
 *                                 managed by Linux. ops->shmem_alloc and
 *                                 ops->shmem_free can be used to override
 *                                 dma_alloc/free_coherent.
 * APPLE_RTKIT_SHMEM_OWNER_RTKIT - shared memory buffers are allocated and
 *                                 managed by RTKit. ops->shmem_map and
 *                                 ops->shmem_unmap must be defined.
 */
#define APPLE_RTKIT_SHMEM_OWNER_LINUX BIT(0)
#define APPLE_RTKIT_SHMEM_OWNER_RTKIT BIT(1)

/*
 * Struct to represent implementation-specific RTKit operations.
 *
 * @flags:        Combination of flags defined above. Exactly one of
 *                APPLE_RTKIT_SHMEM_OWNER_RTKIT or APPLE_RTKIT_SHMEM_OWNER_LINUX
 *                must be set.
 * @crashed:      Called when the co-processor has crashed.
 * @recv_message: Function called when a message from RTKit is recevied
 *                on a non-system endpoint. Called from a worker thread unless
 *                APPLE_RTKIT_RECV_ATOMIC is set.
 * @shmem_map:    Used with APPLE_RTKIT_SHMEM_OWNER_RTKIT to map an
 *                addressed returned by the co-processor into the kernel.
 * @shmem_unmap:  Used with APPLE_RTKIT_SHMEM_OWNER_RTKIT to unmap a previous
 *                mapping created with shmem_map again.
 * @shmem_alloc:  Used with APPLE_RTKIT_SHMEM_OWNER_LINUX to allocate a shared
 *                memory buffer for the co-processor. If not specified
 *                dma_alloc_coherent is used.
 * @shmem_free:   Used with APPLE_RTKIT_SHMEM_OWNER_LINUX to free a shared
 *                memory buffer previously allocated with shmem_alloc. If not
 *                specified dma_free_coherent is used.
 */
struct apple_rtkit_ops {
	unsigned int flags;
	void (*crashed)(void *cookie);
	void (*recv_message)(void *cookie, u8 endpoint, u64 message);
	void __iomem *(*shmem_map)(void *cookie, dma_addr_t addr, size_t len);
	void (*shmem_unmap)(void *cookie, void __iomem *ptr, dma_addr_t addr,
			    size_t len);
	void *(*shmem_alloc)(void *cookie, size_t size, dma_addr_t *dma_handle,
			     gfp_t flag);
	void (*shmem_free)(void *cookie, size_t size, void *cpu_addr,
			   dma_addr_t dma_handle);
};

struct apple_rtkit;

#if IS_ENABLED(CONFIG_APPLE_RTKIT)

/*
 * Initializes the internal state required to handle RTKit. This
 * should usually be called within _probe.
 *
 * @dev: Pointer to the device node this coprocessor is assocated with
 * @cookie: opaque cookie passed to all functions defined in rtkit_ops
 * @mbox_name: mailbox name used to communicate with the co-processor
 * @mbox_idx: mailbox index to be used if mbox_name is NULL
 * @ops: pointer to rtkit_ops to be used for this co-processor
 */
struct apple_rtkit *apple_rtkit_init(struct device *dev, void *cookie,
				     const char *mbox_name, int mbox_idx,
				     const struct apple_rtkit_ops *ops);

/*
 * Dev-res managed version of apple_rtkit_init.
 */
struct apple_rtkit *devm_apple_rtkit_init(struct device *dev, void *cookie,
					  const char *mbox_name, int mbox_idx,
					  const struct apple_rtkit_ops *ops);

/*
 * Free internal structures.
 */
void apple_rtkit_free(struct apple_rtkit *rtk);

/*
 * Reinitialize internal structures. Must only be called with the co-processor
 * is held in reset.
 */
int apple_rtkit_reinit(struct apple_rtkit *rtk);

/*
 * Handle RTKit's boot process. Should be called after the CPU of the
 * co-processor has been started.
 */
int apple_rtkit_boot(struct apple_rtkit *rtk);

/*
 * Hibernate the co-processor.
 */
int apple_rtkit_hibernate(struct apple_rtkit *rtk);

/*
 * Wake the co-processor up from hibernation mode.
 */
int apple_rtkit_wake(struct apple_rtkit *rtk);

/*
 * Shutdown the co-processor
 */
int apple_rtkit_shutdown(struct apple_rtkit *rtk);

/*
 * Checks if RTKit is running and ready to handle messages.
 */
bool apple_rtkit_is_running(struct apple_rtkit *rtk);

/*
 * Checks if RTKit has crashed.
 */
bool apple_rtkit_is_crashed(struct apple_rtkit *rtk);

/*
 * Starts an endpoint. Must be called after boot but before any messages can be
 * sent or received from that endpoint.
 */
int apple_rtkit_start_ep(struct apple_rtkit *rtk, u8 endpoint);

/*
 * Send a message to the given endpoint.
 */
int apple_rtkit_send_message(struct apple_rtkit *rtk, u8 ep, u64 message);

#else

static inline struct apple_rtkit *
apple_rtkit_init(struct device *dev, void *cookie, const char *mbox_name,
		 int mbox_idx, const struct apple_rtkit_ops *ops)
{
	return ERR_PTR(-ENODEV);
}

static inline struct apple_rtkit *
devm_apple_rtkit_init(struct device *dev, void *cookie, const char *mbox_name,
		      int mbox_idx, const struct apple_rtkit_ops *ops)
{
	return ERR_PTR(-ENODEV);
}

static inline void apple_rtkit_free(struct apple_rtkit *rtk)
{
}

static inline int apple_rtkit_reinit(struct apple_rtkit *rtk)
{
	return -ENODEV;
}

static inline int apple_rtkit_boot(struct apple_rtkit *rtk)
{
	return -ENODEV;
}

static inline int apple_rtkit_hibernate(struct apple_rtkit *rtk)
{
	return -ENODEV;
}

static inline int apple_rtkit_wake(struct apple_rtkit *rtk)
{
	return -ENODEV;
}

static inline int apple_rtkit_shutdown(struct apple_rtkit *rtk)
{
	return -ENODEV;
}

static inline bool apple_rtkit_is_running(struct apple_rtkit *rtk)
{
	return false;
}

static inline bool apple_rtkit_is_crashed(struct apple_rtkit *rtk)
{
	return false;
}

static inline int apple_rtkit_start_ep(struct apple_rtkit *rtk, u8 endpoint)
{
	return -ENODEV;
}

static inline int apple_rtkit_send_message(struct apple_rtkit *rtk, u8 ep,
					   u64 message)
{
	return -ENODEV;
}

#endif /* IS_ENABLED(CONFIG_APPLE_RTKIT) */

#endif /* _LINUX_APPLE_RTKIT_H_ */
