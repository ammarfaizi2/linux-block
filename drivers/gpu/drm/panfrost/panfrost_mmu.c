// SPDX-License-Identifier:	GPL-2.0
/* Copyright 2019 Linaro, Ltd, Rob Herring <robh@kernel.org> */
/*
 * Register definitions based on mali_midg_regmap.h
 * (C) COPYRIGHT 2010-2018 ARM Limited. All rights reserved.
 */
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/io-pgtable.h>
#include <linux/iommu.h>
#include <linux/platform_device.h>

#include "panfrost_device.h"
#include "panfrost_mmu.h"
#include "panfrost_gem.h"
#include "panfrost_features.h"

#define MMU_BASE		0x2000

/* MMU regs */
#define MMU_INT_RAWSTAT		0x00
#define MMU_INT_CLEAR		0x04
#define MMU_INT_MASK		0x08
#define MMU_INT_STAT		0x0c

/* AS_COMMAND register commands */
#define AS_COMMAND_NOP		0x00	/* NOP Operation */
#define AS_COMMAND_UPDATE	0x01	/* Broadcasts the values in AS_TRANSTAB and ASn_MEMATTR to all MMUs */
#define AS_COMMAND_LOCK		0x02	/* Issue a lock region command to all MMUs */
#define AS_COMMAND_UNLOCK	0x03	/* Issue a flush region command to all MMUs */
#define AS_COMMAND_FLUSH	0x04	/* Flush all L2 caches then issue a flush region command to all MMUs
					   (deprecated - only for use with T60x) */
#define AS_COMMAND_FLUSH_PT	0x04	/* Flush all L2 caches then issue a flush region command to all MMUs */
#define AS_COMMAND_FLUSH_MEM	0x05	/* Wait for memory accesses to complete, flush all the L1s cache then
					   flush all L2 caches then issue a flush region command to all MMUs */

#define MMU_AS(as)		(0x400 + ((as) << 6))

#define AS_TRANSTAB_LO(as)	(MMU_AS(as) + 0x00) /* (RW) Translation Table Base Address for address space n, low word */
#define AS_TRANSTAB_HI(as)	(MMU_AS(as) + 0x04) /* (RW) Translation Table Base Address for address space n, high word */
#define AS_MEMATTR_LO(as)	(MMU_AS(as) + 0x08) /* (RW) Memory attributes for address space n, low word. */
#define AS_MEMATTR_HI(as)	(MMU_AS(as) + 0x0C) /* (RW) Memory attributes for address space n, high word. */
#define AS_LOCKADDR_LO(as)	(MMU_AS(as) + 0x10) /* (RW) Lock region address for address space n, low word */
#define AS_LOCKADDR_HI(as)	(MMU_AS(as) + 0x14) /* (RW) Lock region address for address space n, high word */
#define AS_COMMAND(as)		(MMU_AS(as) + 0x18) /* (WO) MMU command register for address space n */
#define AS_FAULTSTATUS(as)	(MMU_AS(as) + 0x1C) /* (RO) MMU fault status register for address space n */
#define AS_FAULTADDRESS_LO(as)	(MMU_AS(as) + 0x20) /* (RO) Fault Address for address space n, low word */
#define AS_FAULTADDRESS_HI(as)	(MMU_AS(as) + 0x24) /* (RO) Fault Address for address space n, high word */
#define AS_STATUS(as)		(MMU_AS(as) + 0x28) /* (RO) Status flags for address space n */

/* (RW) Translation table configuration for address space n, low word */
#define AS_TRANSCFG_LO		0x30
/* (RW) Translation table configuration for address space n, high word */
#define AS_TRANSCFG_HI		0x34
/* (RO) Secondary fault address for address space n, low word */
#define AS_FAULTEXTRA_LO	0x38
/* (RO) Secondary fault address for address space n, high word */
#define AS_FAULTEXTRA_HI	0x3C

/*
 * Begin LPAE MMU TRANSTAB register values
 */
#define AS_TRANSTAB_LPAE_ADDR_SPACE_MASK	0xfffffffffffff000
#define AS_TRANSTAB_LPAE_ADRMODE_IDENTITY	0x2
#define AS_TRANSTAB_LPAE_ADRMODE_TABLE		0x3
#define AS_TRANSTAB_LPAE_ADRMODE_MASK		0x3
#define AS_TRANSTAB_LPAE_READ_INNER		BIT(2)
#define AS_TRANSTAB_LPAE_SHARE_OUTER		BIT(4)

#define AS_STATUS_AS_ACTIVE			0x01

#define AS_FAULTSTATUS_ACCESS_TYPE_MASK		(0x3 << 8)
#define AS_FAULTSTATUS_ACCESS_TYPE_ATOMIC	(0x0 << 8)
#define AS_FAULTSTATUS_ACCESS_TYPE_EX		(0x1 << 8)
#define AS_FAULTSTATUS_ACCESS_TYPE_READ		(0x2 << 8)
#define AS_FAULTSTATUS_ACCESS_TYPE_WRITE	(0x3 << 8)

#define mmu_write(dev, reg, data) writel(data, dev->iomem + MMU_BASE + reg)
#define mmu_read(dev, reg) readl(dev->iomem + MMU_BASE + reg)

struct panfrost_mmu {
	struct io_pgtable_ops *pgtbl_ops;
	struct mutex lock;
};

static int wait_ready(struct panfrost_device *pfdev, u32 as_nr)
{
	int ret;
	u32 val;

	/* Wait for the MMU status to indicate there is no active command, in
	 * case one is pending. Do not log remaining register accesses. */
	ret = readl_relaxed_poll_timeout_atomic(pfdev->iomem + MMU_BASE + AS_STATUS(as_nr),
		val, !(val & AS_STATUS_AS_ACTIVE), 10, 1000);

	if (ret)
		dev_err(pfdev->dev, "AS_ACTIVE bit stuck\n");

	return ret;
}

static int write_cmd(struct panfrost_device *pfdev, u32 as_nr, u32 cmd)
{
	int status;

	/* write AS_COMMAND when MMU is ready to accept another command */
	status = wait_ready(pfdev, as_nr);
	if (!status)
		mmu_write(pfdev, AS_COMMAND(as_nr), cmd);

	return status;
}

static void lock_region(struct panfrost_device *pfdev, u32 as_nr,
			u64 iova, size_t size)
{
	u8 region_width;
	u64 region = iova & PAGE_MASK;
	/*
	 * fls returns (given the ASSERT above):
	 * 1 .. 32
	 *
	 * 10 + fls(num_pages)
	 * results in the range (11 .. 42)
	 */

	size = round_up(size, PAGE_SIZE);

	region_width = 10 + fls(size >> PAGE_SHIFT);
	if ((size >> PAGE_SHIFT) != (1ul << (region_width - 11))) {
		/* not pow2, so must go up to the next pow2 */
		region_width += 1;
	}
	region |= region_width;

	/* Lock the region that needs to be updated */
	mmu_write(pfdev, AS_LOCKADDR_LO(as_nr), region & 0xFFFFFFFFUL);
	mmu_write(pfdev, AS_LOCKADDR_HI(as_nr), (region >> 32) & 0xFFFFFFFFUL);
	write_cmd(pfdev, as_nr, AS_COMMAND_LOCK);
}


static int mmu_hw_do_operation(struct panfrost_device *pfdev, u32 as_nr,
		u64 iova, size_t size, u32 op)
{
	if (op != AS_COMMAND_UNLOCK)
		lock_region(pfdev, as_nr, iova, size);

	/* Run the MMU operation */
	write_cmd(pfdev, as_nr, op);

	/* Wait for the flush to complete */
	return wait_ready(pfdev, as_nr);
}

static void mmu_enable(struct panfrost_device *pfdev, u32 as_nr,
		       u64 pgt_base, u64 mem_attr)
{
//	if (kbdev->system_coherency == COHERENCY_ACE)
//		current_setup->transtab |= AS_TRANSTAB_LPAE_SHARE_OUTER;

	pgt_base &= AS_TRANSTAB_LPAE_ADDR_SPACE_MASK;
	pgt_base |= AS_TRANSTAB_LPAE_ADRMODE_TABLE | AS_TRANSTAB_LPAE_READ_INNER;
	mmu_write(pfdev, AS_TRANSTAB_LO(as_nr), pgt_base & 0xffffffffUL);
	mmu_write(pfdev, AS_TRANSTAB_HI(as_nr), pgt_base >> 32);

	mmu_write(pfdev, AS_MEMATTR_LO(as_nr), mem_attr & 0xffffffffUL);
	mmu_write(pfdev, AS_MEMATTR_HI(as_nr), mem_attr >> 32);

	write_cmd(pfdev, as_nr, AS_COMMAND_UPDATE);
}

static void mmu_disable(struct panfrost_device *pfdev, u32 as_nr)
{
	mmu_write(pfdev, AS_TRANSTAB_LO(as_nr), 0);
	mmu_write(pfdev, AS_TRANSTAB_HI(as_nr), 0);

	mmu_write(pfdev, AS_MEMATTR_LO(as_nr), 0);
	mmu_write(pfdev, AS_MEMATTR_HI(as_nr), 0);

	write_cmd(pfdev, as_nr, AS_COMMAND_UPDATE);
}

int panfrost_mmu_map(struct panfrost_gem_object *bo)
{
	struct drm_gem_object *obj = &bo->base.base;
	struct panfrost_device *pfdev = to_panfrost_device(obj->dev);
	struct io_pgtable_ops *ops = pfdev->mmu->pgtbl_ops;
	u64 iova = bo->node.start << PAGE_SHIFT;
	unsigned int count;
	struct scatterlist *sgl;
	struct sg_table *sgt;

	sgt = drm_gem_shmem_get_pages_sgt(obj);
	if (WARN_ON(IS_ERR(sgt)))
		return PTR_ERR(sgt);

	mutex_lock(&pfdev->mmu->lock);

	for_each_sg(sgt->sgl, sgl, sgt->nents, count) {
		unsigned long paddr = sg_dma_address(sgl);
		size_t len = sg_dma_len(sgl);

		while (len) {
			dev_dbg(pfdev->dev, "map: iova=%llx, paddr=%lx, len=%zx", iova, paddr, len);
			ops->map(ops, iova, paddr, SZ_4K, IOMMU_WRITE | IOMMU_READ);
			iova += SZ_4K;
			paddr += SZ_4K;
			len -= SZ_4K;
		}
	}

	mutex_unlock(&pfdev->mmu->lock);
	return 0;
}

void panfrost_mmu_unmap(struct panfrost_gem_object *bo)
{
	struct drm_gem_object *obj = &bo->base.base;
	struct panfrost_device *pfdev = to_panfrost_device(obj->dev);
	struct io_pgtable_ops *ops = pfdev->mmu->pgtbl_ops;
	u64 iova = bo->node.start << PAGE_SHIFT;
	size_t len = bo->node.size << PAGE_SHIFT;
	size_t unmapped_len = 0;

	mutex_lock(&pfdev->mmu->lock);

	while (unmapped_len < len) {
		ops->unmap(ops, iova, SZ_4K);
		iova += SZ_4K;
		unmapped_len += SZ_4K;
	}

	mutex_unlock(&pfdev->mmu->lock);
}

static void mmu_tlb_inv_context_s1(void *cookie)
{
	struct panfrost_device *pfdev = cookie;

	mmu_hw_do_operation(pfdev, 0, 0, ~0UL, AS_COMMAND_FLUSH_MEM);
}

static void mmu_tlb_inv_range_nosync(unsigned long iova, size_t size,
				     size_t granule, bool leaf, void *cookie)
{
	struct panfrost_device *pfdev = cookie;

	dev_dbg(pfdev->dev, "inv_range: iova=%lx, size=%zx, granule=%zx, leaf=%d",
		iova, size, granule, leaf);
	mmu_hw_do_operation(pfdev, 0, iova, size, AS_COMMAND_FLUSH_PT);
}
static void mmu_tlb_sync_context(void *cookie)
{
	//struct panfrost_device *pfdev = cookie;
	// Wait 1000 GPU cycles!?
}

static const struct iommu_gather_ops mmu_tlb_ops = {
	.tlb_flush_all	= mmu_tlb_inv_context_s1,
	.tlb_add_flush	= mmu_tlb_inv_range_nosync,
	.tlb_sync	= mmu_tlb_sync_context,
};

static const char *mmu_exception_name(struct panfrost_device *pfdev,
				      u32 exception_code)
{
	switch (exception_code) {
	case 0xC0 ... 0xC7: return "TRANSLATION_FAULT";
	case 0xC8: return "PERMISSION_FAULT";
	case 0xD0 ... 0xD7: return "TRANSTAB_BUS_FAULT";
	case 0xD8: return "ACCESS_FLAG";
	}

	if (panfrost_has_hw_feature(pfdev, HW_FEATURE_AARCH64_MMU)) {
		switch (exception_code) {
		case 0xC9 ... 0xCF: return "PERMISSION_FAULT";
		case 0xD9 ... 0xDF: return "ACCESS_FLAG";
		case 0xE0 ... 0xE7: return "ADDRESS_SIZE_FAULT";
		case 0xE8 ... 0xEF: return "MEMORY_ATTRIBUTES_FAULT";
		};
	}
	return "UNKNOWN";
}

static const char *access_type_name(struct panfrost_device *pfdev,
		u32 fault_status)
{
	switch (fault_status & AS_FAULTSTATUS_ACCESS_TYPE_MASK) {
	case AS_FAULTSTATUS_ACCESS_TYPE_ATOMIC:
		if (panfrost_has_hw_feature(pfdev, HW_FEATURE_AARCH64_MMU))
			return "ATOMIC";
		else
			return "UNKNOWN";
	case AS_FAULTSTATUS_ACCESS_TYPE_READ:
		return "READ";
	case AS_FAULTSTATUS_ACCESS_TYPE_WRITE:
		return "WRITE";
	case AS_FAULTSTATUS_ACCESS_TYPE_EX:
		return "EXECUTE";
	default:
		WARN_ON(1);
		return NULL;
	}
}

static irqreturn_t panfrost_mmu_irq_handler(int irq, void *data)
{
	struct panfrost_device *pfdev = data;
	u32 status = mmu_read(pfdev, MMU_INT_STAT);
	int i;

	if (!status)
		return IRQ_NONE;

	dev_err(pfdev->dev, "mmu irq status=%x\n", status);

	for (i = 0; status; i++) {
		u32 mask = BIT(i) | BIT(i + 16);
		u64 addr;
		u32 fault_status;
		u32 exception_type;
		u32 access_type;
		u32 source_id;

		if (!(status & mask))
			continue;

		fault_status = mmu_read(pfdev, AS_FAULTSTATUS(i));
		addr = mmu_read(pfdev, AS_FAULTADDRESS_LO(i));
		addr |= (u64)mmu_read(pfdev, AS_FAULTADDRESS_HI(i)) << 32;

		/* decode the fault status */
		exception_type = fault_status & 0xFF;
		access_type = (fault_status >> 8) & 0x3;
		source_id = (fault_status >> 16);

		/* terminal fault, print info about the fault */
		dev_err(pfdev->dev,
			"Unhandled Page fault in AS%d at VA 0x%016llX\n"
			"Reason: %s\n"
			"raw fault status: 0x%X\n"
			"decoded fault status: %s\n"
			"exception type 0x%X: %s\n"
			"access type 0x%X: %s\n"
			"source id 0x%X\n",
			i, addr,
			"TODO",
			fault_status,
			(fault_status & (1 << 10) ? "DECODER FAULT" : "SLAVE FAULT"),
			exception_type, mmu_exception_name(pfdev, exception_type),
			access_type, access_type_name(pfdev, fault_status),
			source_id);

		mmu_write(pfdev, MMU_INT_CLEAR, mask);

		status &= ~mask;
	}

	return IRQ_HANDLED;
};

int panfrost_mmu_init(struct panfrost_device *pfdev)
{
	struct io_pgtable_ops *pgtbl_ops;
	struct io_pgtable_cfg pgtbl_cfg;
	int err, irq;

	pfdev->mmu = devm_kzalloc(pfdev->dev, sizeof(*pfdev->mmu), GFP_KERNEL);
	if (!pfdev->mmu)
		return -ENOMEM;

	mutex_init(&pfdev->mmu->lock);

	irq = platform_get_irq_byname(to_platform_device(pfdev->dev), "mmu");
	if (irq <= 0)
		return -ENODEV;

	err = devm_request_irq(pfdev->dev, irq, panfrost_mmu_irq_handler,
			       IRQF_SHARED, "mmu", pfdev);

	if (err) {
		dev_err(pfdev->dev, "failed to request mmu irq");
		return err;
	}
	mmu_write(pfdev, MMU_INT_CLEAR, ~0);
	mmu_write(pfdev, MMU_INT_MASK, ~0);

	pgtbl_cfg = (struct io_pgtable_cfg) {
		.pgsize_bitmap	= SZ_4K, // | SZ_2M | SZ_1G),
		.ias		= 48,
		.oas		= 40,	/* Should come from dma mask? */
		.tlb		= &mmu_tlb_ops,
		.iommu_dev	= pfdev->dev,
	};

	pgtbl_ops = alloc_io_pgtable_ops(ARM_MALI_LPAE, &pgtbl_cfg, pfdev);
	if (!pgtbl_ops)
		return -ENOMEM;

	pfdev->mmu->pgtbl_ops = pgtbl_ops;

	/* Need to revisit mem attrs.
	 * NC is the default, Mali driver is inner WT.
	 */
	mmu_enable(pfdev, 0, pgtbl_cfg.arm_lpae_s1_cfg.ttbr[0],
		   pgtbl_cfg.arm_lpae_s1_cfg.mair[0]);

	return 0;
}

void panfrost_mmu_fini(struct panfrost_device *pfdev)
{
	mmu_write(pfdev, MMU_INT_MASK, 0);
	mmu_disable(pfdev, 0);

	free_io_pgtable_ops(pfdev->mmu->pgtbl_ops);
}
