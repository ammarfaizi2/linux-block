/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_DMA_H
#define __ASM_DMA_H

#ifndef __ASSEMBLY__

#include <linux/types.h>

extern phys_addr_t arm64_dma_phys_limit;
#define ARCH_LOW_ADDRESS_LIMIT	(arm64_dma_phys_limit - 1)

#define MAX_DMA_ADDRESS PAGE_OFFSET

extern int request_dma(unsigned int dmanr, const char *device_id);
extern void free_dma(unsigned int dmanr);

#endif /* __ASSEMBLY__ */

#endif /* __ASM_DMA_H */
