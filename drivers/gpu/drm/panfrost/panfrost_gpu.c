// SPDX-License-Identifier: GPL-2.0
/* Copyright 2018 Marty E. Plummer <hanetzer@startmail.com> */
/* Copyright 2019 Linaro, Ltd., Rob Herring <robh@kernel.org> */
/* Copyright 2019 Collabora ltd. */
/*
 * Register definitions based on mali_midg_regmap.h
 * (C) COPYRIGHT 2010-2018 ARM Limited. All rights reserved.
 */
#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/platform_device.h>

#include "panfrost_device.h"
#include "panfrost_features.h"
#include "panfrost_issues.h"
#include "panfrost_gpu.h"

#define GPU_ID				0x00
#define GPU_L2_FEATURES			0x004	/* (RO) Level 2 cache features */
#define GPU_CORE_FEATURES		0x008	/* (RO) Shader Core Features */
#define GPU_TILER_FEATURES		0x00C	/* (RO) Tiler Features */
#define GPU_MEM_FEATURES		0x010	/* (RO) Memory system features */
#define   GROUPS_L2_COHERENT		BIT(0)	/* Cores groups are l2 coherent */

#define GPU_MMU_FEATURES		0x014	/* (RO) MMU features */
#define GPU_AS_PRESENT			0x018	/* (RO) Address space slots present */
#define GPU_JS_PRESENT			0x01C	/* (RO) Job slots present */


#define GPU_INT_RAWSTAT			0x20
#define GPU_INT_CLEAR			0x24
#define GPU_INT_MASK			0x28
#define GPU_INT_STAT			0x2c
#define   GPU_IRQ_FAULT			BIT(0)
#define   GPU_IRQ_MULTIPLE_FAULT	BIT(7)
#define   GPU_IRQ_RESET_COMPLETED	BIT(8)
#define   GPU_IRQ_POWER_CHANGED		BIT(9)
#define   GPU_IRQ_POWER_CHANGED_ALL	BIT(10)
#define   GPU_IRQ_PERFCNT_SAMPLE_COMPLETED BIT(16)
#define   GPU_IRQ_CLEAN_CACHES_COMPLETED BIT(17)
#define   GPU_IRQ_MASK_ALL			 \
	  (GPU_IRQ_FAULT			|\
	   GPU_IRQ_MULTIPLE_FAULT		|\
	   GPU_IRQ_RESET_COMPLETED		|\
	   GPU_IRQ_POWER_CHANGED		|\
	   GPU_IRQ_POWER_CHANGED_ALL		|\
	   GPU_IRQ_PERFCNT_SAMPLE_COMPLETED	|\
	   GPU_IRQ_CLEAN_CACHES_COMPLETED)
#define GPU_IRQ_MASK_ERROR	   		\
	(					\
	 GPU_IRQ_FAULT				|\
	 GPU_IRQ_MULTIPLE_FAULT)
#define GPU_CMD				0x30
#define   GPU_CMD_SOFT_RESET		0x01
#define GPU_STATUS			0x34
#define GPU_LATEST_FLUSH_ID		0x38


#define GPU_THREAD_MAX_THREADS		0x0A0	/* (RO) Maximum number of threads per core */
#define GPU_THREAD_MAX_WORKGROUP_SIZE	0x0A4	/* (RO) Maximum workgroup size */
#define GPU_THREAD_MAX_BARRIER_SIZE	0x0A8	/* (RO) Maximum threads waiting at a barrier */
#define GPU_THREAD_FEATURES		0x0AC	/* (RO) Thread features */
#define GPU_THREAD_TLS_ALLOC		0x310   /* (RO) Number of threads per core that
						 * TLS must be allocated for */

#define GPU_TEXTURE_FEATURES(n)		(0x0B0 + ((n) * 4))
#define GPU_JS_FEATURES(n)		(0x0C0 + ((n) * 4))

#define GPU_SHADER_PRESENT_LO		0x100	/* (RO) Shader core present bitmap, low word */
#define GPU_SHADER_PRESENT_HI		0x104	/* (RO) Shader core present bitmap, high word */
#define GPU_TILER_PRESENT_LO		0x110	/* (RO) Tiler core present bitmap, low word */
#define GPU_TILER_PRESENT_HI		0x114	/* (RO) Tiler core present bitmap, high word */

#define GPU_L2_PRESENT_LO		0x120	/* (RO) Level 2 cache present bitmap, low word */
#define GPU_L2_PRESENT_HI		0x124	/* (RO) Level 2 cache present bitmap, high word */

#define GPU_COHERENCY_FEATURES		0x300	/* (RO) Coherency features present */

#define GPU_STACK_PRESENT_LO		0xE00   /* (RO) Core stack present bitmap, low word */
#define GPU_STACK_PRESENT_HI		0xE04   /* (RO) Core stack present bitmap, high word */

#define SHADER_READY_LO         0x140	/* (RO) Shader core ready bitmap, low word */
#define SHADER_READY_HI         0x144	/* (RO) Shader core ready bitmap, high word */

#define TILER_READY_LO          0x150	/* (RO) Tiler core ready bitmap, low word */
#define TILER_READY_HI          0x154	/* (RO) Tiler core ready bitmap, high word */

#define L2_READY_LO             0x160	/* (RO) Level 2 cache ready bitmap, low word */
#define L2_READY_HI             0x164	/* (RO) Level 2 cache ready bitmap, high word */

#define STACK_READY_LO          0xE10   /* (RO) Core stack ready bitmap, low word */
#define STACK_READY_HI          0xE14   /* (RO) Core stack ready bitmap, high word */


#define SHADER_PWRON_LO         0x180	/* (WO) Shader core power on bitmap, low word */
#define SHADER_PWRON_HI         0x184	/* (WO) Shader core power on bitmap, high word */

#define TILER_PWRON_LO          0x190	/* (WO) Tiler core power on bitmap, low word */
#define TILER_PWRON_HI          0x194	/* (WO) Tiler core power on bitmap, high word */

#define L2_PWRON_LO             0x1A0	/* (WO) Level 2 cache power on bitmap, low word */
#define L2_PWRON_HI             0x1A4	/* (WO) Level 2 cache power on bitmap, high word */

#define STACK_PWRON_LO          0xE20   /* (RO) Core stack power on bitmap, low word */
#define STACK_PWRON_HI          0xE24   /* (RO) Core stack power on bitmap, high word */


#define SHADER_PWROFF_LO        0x1C0	/* (WO) Shader core power off bitmap, low word */
#define SHADER_PWROFF_HI        0x1C4	/* (WO) Shader core power off bitmap, high word */

#define TILER_PWROFF_LO         0x1D0	/* (WO) Tiler core power off bitmap, low word */
#define TILER_PWROFF_HI         0x1D4	/* (WO) Tiler core power off bitmap, high word */

#define L2_PWROFF_LO            0x1E0	/* (WO) Level 2 cache power off bitmap, low word */
#define L2_PWROFF_HI            0x1E4	/* (WO) Level 2 cache power off bitmap, high word */

#define STACK_PWROFF_LO         0xE30   /* (RO) Core stack power off bitmap, low word */
#define STACK_PWROFF_HI         0xE34   /* (RO) Core stack power off bitmap, high word */


#define SHADER_PWRTRANS_LO      0x200	/* (RO) Shader core power transition bitmap, low word */
#define SHADER_PWRTRANS_HI      0x204	/* (RO) Shader core power transition bitmap, high word */

#define TILER_PWRTRANS_LO       0x210	/* (RO) Tiler core power transition bitmap, low word */
#define TILER_PWRTRANS_HI       0x214	/* (RO) Tiler core power transition bitmap, high word */

#define L2_PWRTRANS_LO          0x220	/* (RO) Level 2 cache power transition bitmap, low word */
#define L2_PWRTRANS_HI          0x224	/* (RO) Level 2 cache power transition bitmap, high word */

#define STACK_PWRTRANS_LO       0xE40   /* (RO) Core stack power transition bitmap, low word */
#define STACK_PWRTRANS_HI       0xE44   /* (RO) Core stack power transition bitmap, high word */


#define SHADER_PWRACTIVE_LO     0x240	/* (RO) Shader core active bitmap, low word */
#define SHADER_PWRACTIVE_HI     0x244	/* (RO) Shader core active bitmap, high word */

#define TILER_PWRACTIVE_LO      0x250	/* (RO) Tiler core active bitmap, low word */
#define TILER_PWRACTIVE_HI      0x254	/* (RO) Tiler core active bitmap, high word */

#define L2_PWRACTIVE_LO         0x260	/* (RO) Level 2 cache active bitmap, low word */
#define L2_PWRACTIVE_HI         0x264	/* (RO) Level 2 cache active bitmap, high word */

#define GPU_JM_CONFIG		0xF00   /* (RW) Job Manager configuration register (Implementation specific register) */
#define GPU_SHADER_CONFIG	0xF04	/* (RW) Shader core configuration settings (Implementation specific register) */
#define GPU_TILER_CONFIG	0xF08   /* (RW) Tiler core configuration settings (Implementation specific register) */
#define GPU_L2_MMU_CONFIG	0xF0C	/* (RW) Configuration of the L2 cache and MMU (Implementation specific register) */

/* L2_MMU_CONFIG register */
#define L2_MMU_CONFIG_ALLOW_SNOOP_DISPARITY_SHIFT       (23)
#define L2_MMU_CONFIG_ALLOW_SNOOP_DISPARITY             (0x1 << L2_MMU_CONFIG_ALLOW_SNOOP_DISPARITY_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT        (24)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS              (0x3 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_OCTANT       (0x1 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_QUARTER      (0x2 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_HALF         (0x3 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)

#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT       (26)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES             (0x3 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_OCTANT      (0x1 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_QUARTER     (0x2 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)
#define L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_HALF        (0x3 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)

#define L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_READS_SHIFT      (12)
#define L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_READS            (0x7 << L2_MMU_CONFIG_LIMIT_EXTERNAL_READS_SHIFT)

#define L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_WRITES_SHIFT     (15)
#define L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_WRITES           (0x7 << L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES_SHIFT)

/* SHADER_CONFIG register */

#define SC_ALT_COUNTERS             (1ul << 3)
#define SC_OVERRIDE_FWD_PIXEL_KILL  (1ul << 4)
#define SC_SDC_DISABLE_OQ_DISCARD   (1ul << 6)
#define SC_LS_ALLOW_ATTR_TYPES      (1ul << 16)
#define SC_LS_PAUSEBUFFER_DISABLE   (1ul << 16)
#define SC_TLS_HASH_ENABLE          (1ul << 17)
#define SC_LS_ATTR_CHECK_DISABLE    (1ul << 18)
#define SC_ENABLE_TEXGRD_FLAGS      (1ul << 25)
/* End SHADER_CONFIG register */

/* TILER_CONFIG register */

#define TC_CLOCK_GATE_OVERRIDE      (1ul << 0)

/* JM_CONFIG register */

#define JM_TIMESTAMP_OVERRIDE  (1ul << 0)
#define JM_CLOCK_GATE_OVERRIDE (1ul << 1)
#define JM_JOB_THROTTLE_ENABLE (1ul << 2)
#define JM_JOB_THROTTLE_LIMIT_SHIFT (3)
#define JM_MAX_JOB_THROTTLE_LIMIT (0x3F)
#define JM_FORCE_COHERENCY_FEATURES_SHIFT (2)
#define JM_IDVS_GROUP_SIZE_SHIFT (16)
#define JM_MAX_IDVS_GROUP_SIZE (0x3F)


#define gpu_write(dev, reg, data) writel(data, dev->iomem + reg)
#define gpu_read(dev, reg) readl(dev->iomem + reg)

static irqreturn_t panfrost_gpu_irq_handler(int irq, void *data)
{
	struct panfrost_device *pfdev = data;
	u32 state = gpu_read(pfdev, GPU_INT_STAT);
	u32 status = gpu_read(pfdev, GPU_STATUS);
	bool done = false;

	if (!state)
		return IRQ_NONE;

	if (state & GPU_IRQ_MASK_ERROR) {
		dev_err(pfdev->dev, "gpu error irq state=%x status=%x\n",
			state, status);

		gpu_write(pfdev, GPU_INT_MASK, 0);

		done = true;
	}

	gpu_write(pfdev, GPU_INT_CLEAR, state);

	return IRQ_HANDLED;
}

static int panfrost_gpu_soft_reset(struct panfrost_device *pfdev)
{
	int ret;
	u32 val;

	gpu_write(pfdev, GPU_INT_MASK, 0);
	gpu_write(pfdev, GPU_INT_CLEAR, GPU_IRQ_RESET_COMPLETED);
	gpu_write(pfdev, GPU_CMD, GPU_CMD_SOFT_RESET);

	ret = readl_relaxed_poll_timeout(pfdev->iomem + GPU_INT_RAWSTAT,
		val, val & GPU_IRQ_RESET_COMPLETED, 100, 10000);

	if (ret) {
		dev_err(pfdev->dev, "gpu soft reset timed out\n");
		return ret;
	}

	gpu_write(pfdev, GPU_INT_CLEAR, GPU_IRQ_MASK_ALL);
	gpu_write(pfdev, GPU_INT_MASK, GPU_IRQ_MASK_ALL);

	return 0;
}

static void panfrost_gpu_init_quirks(struct panfrost_device *pfdev)
{
	u32 sc = 0, tiler = 0, jm = 0, mmu = 0;

	mmu = gpu_read(pfdev, GPU_L2_MMU_CONFIG);

	// Need more version detection
	if (pfdev->features.id == 0x0860) {
		sc = SC_LS_ALLOW_ATTR_TYPES;
		tiler = TC_CLOCK_GATE_OVERRIDE;
		jm = JM_MAX_JOB_THROTTLE_LIMIT << JM_JOB_THROTTLE_LIMIT_SHIFT;
		mmu &= ~(L2_MMU_CONFIG_LIMIT_EXTERNAL_READS | L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES);
	}

	gpu_write(pfdev, GPU_SHADER_CONFIG, sc);
	gpu_write(pfdev, GPU_TILER_CONFIG, tiler);
	gpu_write(pfdev, GPU_L2_MMU_CONFIG, mmu);
	gpu_write(pfdev, GPU_JM_CONFIG, jm);
}

#define MAX_HW_REVS 6

struct panfrost_model {
	const char *name;
	u32 id;
	u32 id_mask;
	u64 features;
	u64 issues;
	struct {
		u32 revision;
		u64 issues;
	} revs[MAX_HW_REVS];
};

#define GPU_MODEL(_name, _id, _mask, ...) \
{\
	.name = __stringify(_name),				\
	.id = _id,						\
	.id_mask = _mask,					\
	.features = hw_features_##_name,			\
	.issues = hw_issues_##_name,			\
	.revs = { __VA_ARGS__ },				\
}
#define GPU_MODEL_MIDGARD(name, id, ...) GPU_MODEL(name, id, 0xfff, __VA_ARGS__)
#define GPU_MODEL_BIFROST(name, id, ...) GPU_MODEL(name, id, 0xf00f, __VA_ARGS__)

#define GPU_REV_EXT(name, _rev, _p, _s, stat) \
{\
	.revision = (_rev) << 12 | (_p) << 4 | (_s),		\
	.issues = hw_issues_##name##_r##_rev##p##_p##stat,	\
}
#define GPU_REV(name, r, p) GPU_REV_EXT(name, r, p, 0, )

static const struct panfrost_model gpu_models[] = {
	/* T60x has an oddball version */
	GPU_MODEL_MIDGARD(t600, 0x600,
		GPU_REV_EXT(t600, 0, 0, 1, _15dev0)),
	GPU_MODEL_MIDGARD(t620, 0x620,
		GPU_REV(t620, 0, 1), GPU_REV(t620, 1, 0)),
	GPU_MODEL_MIDGARD(t720, 0x720),
	GPU_MODEL_MIDGARD(t760, 0x750,
		GPU_REV(t760, 0, 0), GPU_REV(t760, 0, 1),
		GPU_REV_EXT(t760, 0, 1, 0, _50rel0),
		GPU_REV(t760, 0, 2), GPU_REV(t760, 0, 3)),
	GPU_MODEL_MIDGARD(t820, 0x820),
	GPU_MODEL_MIDGARD(t830, 0x830),
	GPU_MODEL_MIDGARD(t860, 0x860),
	GPU_MODEL_MIDGARD(t880, 0x880),

	GPU_MODEL_BIFROST(g71, 0x6000,
		GPU_REV_EXT(g71, 0, 0, 1, _05dev0)),
	GPU_MODEL_BIFROST(g72, 0x6001),
	GPU_MODEL_BIFROST(g51, 0x7000),
	GPU_MODEL_BIFROST(g76, 0x7001),
	GPU_MODEL_BIFROST(g52, 0x7002),
	GPU_MODEL_BIFROST(g31, 0x7003,
		GPU_REV(g31, 1, 0)),
};

static void panfrost_gpu_init_features(struct panfrost_device *pfdev)
{
	u32 gpu_id, num_js, major, minor, status, rev;
	const char *name = "unknown";
	u64 hw_feat = 0;
	u64 hw_issues = hw_issues_all;
	const struct panfrost_model *model;
	int i;

	pfdev->features.l2_features = gpu_read(pfdev, GPU_L2_FEATURES);
	pfdev->features.core_features = gpu_read(pfdev, GPU_CORE_FEATURES);
	pfdev->features.tiler_features = gpu_read(pfdev, GPU_TILER_FEATURES);
	pfdev->features.mem_features = gpu_read(pfdev, GPU_MEM_FEATURES);
	pfdev->features.mmu_features = gpu_read(pfdev, GPU_MMU_FEATURES);
	pfdev->features.thread_features = gpu_read(pfdev, GPU_THREAD_FEATURES);
	pfdev->features.coherency_features = gpu_read(pfdev, GPU_COHERENCY_FEATURES);
	for (i = 0; i < 4; i++)
		pfdev->features.texture_features[i] = gpu_read(pfdev, GPU_TEXTURE_FEATURES(i));

	pfdev->features.as_present = gpu_read(pfdev, GPU_AS_PRESENT);

	pfdev->features.js_present = gpu_read(pfdev, GPU_JS_PRESENT);
	num_js = hweight32(pfdev->features.js_present);
	for (i = 0; i < num_js; i++)
		pfdev->features.js_features[i] = gpu_read(pfdev, GPU_JS_FEATURES(i));

	pfdev->features.shader_present = gpu_read(pfdev, GPU_SHADER_PRESENT_LO);
	pfdev->features.shader_present |= (u64)gpu_read(pfdev, GPU_SHADER_PRESENT_HI) << 32;

	pfdev->features.tiler_present = gpu_read(pfdev, GPU_TILER_PRESENT_LO);
	pfdev->features.tiler_present |= (u64)gpu_read(pfdev, GPU_TILER_PRESENT_HI) << 32;

	pfdev->features.l2_present = gpu_read(pfdev, GPU_L2_PRESENT_LO);
	pfdev->features.l2_present |= (u64)gpu_read(pfdev, GPU_L2_PRESENT_HI) << 32;
	pfdev->features.nr_core_groups = hweight64(pfdev->features.l2_present);

	pfdev->features.stack_present = gpu_read(pfdev, GPU_STACK_PRESENT_LO);
	pfdev->features.stack_present |= (u64)gpu_read(pfdev, GPU_STACK_PRESENT_HI) << 32;

	gpu_id = gpu_read(pfdev, GPU_ID);
	pfdev->features.revision = gpu_id & 0xffff;
	pfdev->features.id = gpu_id >> 16;

	/* The T60x has an oddball ID value. Fix it up to the standard Midgard
	 * format so we (and userspace) don't have to special case it.
	 */
	if (pfdev->features.id == 0x6956)
		pfdev->features.id = 0x0600;

	major = (pfdev->features.revision >> 12) & 0xf;
	minor = (pfdev->features.revision >> 4) & 0xff;
	status = pfdev->features.revision & 0xf;
	rev = pfdev->features.revision;

	gpu_id = pfdev->features.id;

	for (model = gpu_models; model->name; model++) {
		if ((gpu_id & model->id_mask) != model->id)
			continue;

		name = model->name;
		hw_feat = model->features;
		hw_issues |= model->issues;
		for (i = 0; i < MAX_HW_REVS; i++) {
			if ((model->revs[i].revision != rev) &&
			    (model->revs[i].revision != (rev & ~0xf)))
				continue;
			hw_issues |= model->revs[i].issues;
			break;
		}

		break;
	}

	bitmap_from_u64(pfdev->features.hw_features, hw_feat);
	bitmap_from_u64(pfdev->features.hw_issues, hw_issues);

	dev_info(pfdev->dev, "mali-%s id 0x%x major 0x%x minor 0x%x status 0x%x",
		 name, gpu_id, major, minor, status);
	dev_info(pfdev->dev, "features: %64pb, issues: %64pb",
		 pfdev->features.hw_features,
		 pfdev->features.hw_issues);

	dev_info(pfdev->dev, "Features: L2:0x%08x Shader:0x%08x Tiler:0x%08x Mem:0x%0x MMU:0x%08x AS:0x%x JS:0x%x",
		 gpu_read(pfdev, GPU_L2_FEATURES),
		 gpu_read(pfdev, GPU_CORE_FEATURES),
		 gpu_read(pfdev, GPU_TILER_FEATURES),
		 gpu_read(pfdev, GPU_MEM_FEATURES),
		 gpu_read(pfdev, GPU_MMU_FEATURES),
		 gpu_read(pfdev, GPU_AS_PRESENT),
		 gpu_read(pfdev, GPU_JS_PRESENT));

	dev_info(pfdev->dev, "shader_present=0x%0llx", pfdev->features.shader_present);
}

static void panfrost_gpu_power_on(struct panfrost_device *pfdev)
{
	int ret;
	u32 val;

	/* Just turn on everything for now */
	gpu_write(pfdev, SHADER_PWRON_LO, pfdev->features.shader_present);
	ret = readl_relaxed_poll_timeout(pfdev->iomem + SHADER_READY_LO,
		val, val == pfdev->features.shader_present, 100, 1000);

	gpu_write(pfdev, TILER_PWRON_LO, pfdev->features.tiler_present);
	ret |= readl_relaxed_poll_timeout(pfdev->iomem + TILER_READY_LO,
		val, val == pfdev->features.tiler_present, 100, 1000);

	gpu_write(pfdev, L2_PWRON_LO, pfdev->features.l2_present);
	ret |= readl_relaxed_poll_timeout(pfdev->iomem + L2_READY_LO,
		val, val == pfdev->features.l2_present, 100, 1000);

	gpu_write(pfdev, STACK_PWRON_LO, pfdev->features.stack_present);
	ret |= readl_relaxed_poll_timeout(pfdev->iomem + STACK_READY_LO,
		val, val == pfdev->features.stack_present, 100, 1000);

	if (ret)
		dev_err(pfdev->dev, "error powering up gpu");
}

int panfrost_gpu_init(struct panfrost_device *pfdev)
{
	int err, irq;

	err = panfrost_gpu_soft_reset(pfdev);
	if (err)
		return err;

	panfrost_gpu_init_features(pfdev);

	irq = platform_get_irq_byname(to_platform_device(pfdev->dev), "gpu");
	if (irq <= 0)
		return -ENODEV;

	err = devm_request_irq(pfdev->dev, irq, panfrost_gpu_irq_handler,
			       IRQF_SHARED, "gpu", pfdev);
	if (err) {
		dev_err(pfdev->dev, "failed to request gpu irq");
		return err;
	}

	panfrost_gpu_init_quirks(pfdev);
	panfrost_gpu_power_on(pfdev);

	return 0;
}

void panfrost_gpu_fini(struct panfrost_device *pfdev)
{

}

u32 panfrost_gpu_get_latest_flush_id(struct panfrost_device *pfdev)
{
	if (panfrost_has_hw_feature(pfdev, HW_FEATURE_FLUSH_REDUCTION))
		return gpu_read(pfdev, GPU_LATEST_FLUSH_ID);
	return 0;
}
