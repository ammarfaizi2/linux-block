/*
 * Performance events:
 *
 *    Copyright (C) 2008-2009, Thomas Gleixner <tglx@linutronix.de>
 *    Copyright (C) 2008-2011, Red Hat, Inc., Ingo Molnar
 *    Copyright (C) 2008-2011, Red Hat, Inc., Peter Zijlstra
 *
 * Data type definitions, declarations, prototypes.
 *
 *    Started by: Thomas Gleixner and Ingo Molnar
 *
 * For licencing details see kernel-base/COPYING
 */
#ifndef _LINUX_PERF_EVENT_TYPES_H
#define _LINUX_PERF_EVENT_TYPES_H

#include <linux/smp_api.h>
#include <linux/lockdep_api.h>
#include <linux/cred.h>
#include <linux/cgroup_api.h>
#include <uapi/linux/perf_event.h>
#include <uapi/linux/bpf_perf_event.h>

/*
 * Kernel-internal data types and definitions:
 */

#ifdef CONFIG_PERF_EVENTS
# include <asm/perf_event.h>
# include <asm/local64.h>
#endif

#define PERF_GUEST_ACTIVE	0x01
#define PERF_GUEST_USER	0x02

struct perf_guest_info_callbacks {
	unsigned int			(*state)(void);
	unsigned long			(*get_ip)(void);
	unsigned int			(*handle_intel_pt_intr)(void);
};

#ifdef CONFIG_HAVE_HW_BREAKPOINT
#include <asm/hw_breakpoint.h>
#endif

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/fs.h>
#include <linux/pid_namespace.h>
#include <linux/workqueue.h>
#include <linux/ftrace.h>
#include <linux/cpu.h>
#include <linux/irq_work.h>
#include <linux/static_key.h>
#include <linux/jump_label_ratelimit.h>
#include <linux/atomic.h>
#include <linux/sysfs.h>
#include <linux/perf_regs.h>
#include <linux/cgroup.h>
#include <linux/refcount.h>
#include <linux/security.h>
#include <linux/static_call.h>
#include <asm/local.h>

struct perf_callchain_entry {
	__u64				nr;
	__u64				ip[]; /* /proc/sys/kernel/perf_event_max_stack */
};

struct perf_callchain_entry_ctx {
	struct perf_callchain_entry *entry;
	u32			    max_stack;
	u32			    nr;
	short			    contexts;
	bool			    contexts_maxed;
};

typedef unsigned long (*perf_copy_f)(void *dst, const void *src,
				     unsigned long off, unsigned long len);

struct perf_raw_frag {
	union {
		struct perf_raw_frag	*next;
		unsigned long		pad;
	};
	perf_copy_f			copy;
	void				*data;
	u32				size;
} __packed;

struct perf_raw_record {
	struct perf_raw_frag		frag;
	u32				size;
};

/*
 * branch stack layout:
 *  nr: number of taken branches stored in entries[]
 *  hw_idx: The low level index of raw branch records
 *          for the most recent branch.
 *          -1ULL means invalid/unknown.
 *
 * Note that nr can vary from sample to sample
 * branches (to, from) are stored from most recent
 * to least recent, i.e., entries[0] contains the most
 * recent branch.
 * The entries[] is an abstraction of raw branch records,
 * which may not be stored in age order in HW, e.g. Intel LBR.
 * The hw_idx is to expose the low level index of raw
 * branch record for the most recent branch aka entries[0].
 * The hw_idx index is between -1 (unknown) and max depth,
 * which can be retrieved in /sys/devices/cpu/caps/branches.
 * For the architectures whose raw branch records are
 * already stored in age order, the hw_idx should be 0.
 */
struct perf_branch_stack {
	__u64				nr;
	__u64				hw_idx;
	struct perf_branch_entry	entries[];
};

struct task_struct;

/*
 * extra PMU register associated with an event
 */
struct hw_perf_event_extra {
	u64		config;	/* register value */
	unsigned int	reg;	/* register address or index */
	int		alloc;	/* extra register already allocated */
	int		idx;	/* index in shared_regs->regs[] */
};

/**
 * hw_perf_event::flag values
 *
 * PERF_EVENT_FLAG_ARCH bits are reserved for architecture-specific
 * usage.
 */
#define PERF_EVENT_FLAG_ARCH			0x0000ffff
#define PERF_EVENT_FLAG_USER_READ_CNT		0x80000000

/**
 * struct hw_perf_event - performance event hardware details:
 */
struct hw_perf_event {
#ifdef CONFIG_PERF_EVENTS
	union {
		struct { /* hardware */
			u64		config;
			u64		last_tag;
			unsigned long	config_base;
			unsigned long	event_base;
			int		event_base_rdpmc;
			int		idx;
			int		last_cpu;
			int		flags;

			struct hw_perf_event_extra extra_reg;
			struct hw_perf_event_extra branch_reg;
		};
		struct { /* software */
			struct hrtimer	hrtimer;
		};
		struct { /* tracepoint */
			/* for tp_event->class */
			struct list_head	tp_list;
		};
		struct { /* amd_power */
			u64	pwr_acc;
			u64	ptsc;
		};
#ifdef CONFIG_HAVE_HW_BREAKPOINT
		struct { /* breakpoint */
			/*
			 * Crufty hack to avoid the chicken and egg
			 * problem hw_breakpoint has with context
			 * creation and event initalization.
			 */
			struct arch_hw_breakpoint	info;
			struct list_head		bp_list;
		};
#endif
		struct { /* amd_iommu */
			u8	iommu_bank;
			u8	iommu_cntr;
			u16	padding;
			u64	conf;
			u64	conf1;
		};
	};
	/*
	 * If the event is a per task event, this will point to the task in
	 * question. See the comment in perf_event_alloc().
	 */
	struct task_struct		*target;

	/*
	 * PMU would store hardware filter configuration
	 * here.
	 */
	void				*addr_filters;

	/* Last sync'ed generation of filters */
	unsigned long			addr_filters_gen;

/*
 * hw_perf_event::state flags; used to track the PERF_EF_* state.
 */
#define PERF_HES_STOPPED	0x01 /* the counter is stopped */
#define PERF_HES_UPTODATE	0x02 /* event->count up-to-date */
#define PERF_HES_ARCH		0x04

	int				state;

	/*
	 * The last observed hardware counter value, updated with a
	 * local64_cmpxchg() such that pmu::read() can be called nested.
	 */
	local64_t			prev_count;

	/*
	 * The period to start the next sample with.
	 */
	u64				sample_period;

	union {
		struct { /* Sampling */
			/*
			 * The period we started this sample with.
			 */
			u64				last_period;

			/*
			 * However much is left of the current period;
			 * note that this is a full 64bit value and
			 * allows for generation of periods longer
			 * than hardware might allow.
			 */
			local64_t			period_left;
		};
		struct { /* Topdown events counting for context switch */
			u64				saved_metric;
			u64				saved_slots;
		};
	};

	/*
	 * State for throttling the event, see __perf_event_overflow() and
	 * perf_adjust_freq_unthr_context().
	 */
	u64                             interrupts_seq;
	u64				interrupts;

	/*
	 * State for freq target events, see __perf_event_overflow() and
	 * perf_adjust_freq_unthr_context().
	 */
	u64				freq_time_stamp;
	u64				freq_count_stamp;
#endif
};

struct perf_event;

/*
 * Common implementation detail of pmu::{start,commit,cancel}_txn
 */
#define PERF_PMU_TXN_ADD  0x1		/* txn to add/schedule event on PMU */
#define PERF_PMU_TXN_READ 0x2		/* txn to read event group from PMU */

/**
 * pmu::capabilities flags
 */
#define PERF_PMU_CAP_NO_INTERRUPT		0x0001
#define PERF_PMU_CAP_NO_NMI			0x0002
#define PERF_PMU_CAP_AUX_NO_SG			0x0004
#define PERF_PMU_CAP_EXTENDED_REGS		0x0008
#define PERF_PMU_CAP_EXCLUSIVE			0x0010
#define PERF_PMU_CAP_ITRACE			0x0020
#define PERF_PMU_CAP_HETEROGENEOUS_CPUS		0x0040
#define PERF_PMU_CAP_NO_EXCLUDE			0x0080
#define PERF_PMU_CAP_AUX_OUTPUT			0x0100
#define PERF_PMU_CAP_EXTENDED_HW_TYPE		0x0200

struct perf_output_handle;
struct perf_event_context;

/**
 * struct pmu - generic performance monitoring unit
 */
struct pmu {
	struct list_head		entry;

	struct module			*module;
	struct device			*dev;
	const struct attribute_group	**attr_groups;
	const struct attribute_group	**attr_update;
	const char			*name;
	int				type;

	/*
	 * various common per-pmu feature flags
	 */
	int				capabilities;

	int __percpu			*pmu_disable_count;
	struct perf_cpu_context __percpu *pmu_cpu_context;
	atomic_t			exclusive_cnt; /* < 0: cpu; > 0: tsk */
	int				task_ctx_nr;
	int				hrtimer_interval_ms;

	/* number of address filters this PMU can do */
	unsigned int			nr_addr_filters;

	/*
	 * Fully disable/enable this PMU, can be used to protect from the PMI
	 * as well as for lazy/batch writing of the MSRs.
	 */
	void (*pmu_enable)		(struct pmu *pmu); /* optional */
	void (*pmu_disable)		(struct pmu *pmu); /* optional */

	/*
	 * Try and initialize the event for this PMU.
	 *
	 * Returns:
	 *  -ENOENT	-- @event is not for this PMU
	 *
	 *  -ENODEV	-- @event is for this PMU but PMU not present
	 *  -EBUSY	-- @event is for this PMU but PMU temporarily unavailable
	 *  -EINVAL	-- @event is for this PMU but @event is not valid
	 *  -EOPNOTSUPP -- @event is for this PMU, @event is valid, but not supported
	 *  -EACCES	-- @event is for this PMU, @event is valid, but no privileges
	 *
	 *  0		-- @event is for this PMU and valid
	 *
	 * Other error return values are allowed.
	 */
	int (*event_init)		(struct perf_event *event);

	/*
	 * Notification that the event was mapped or unmapped.  Called
	 * in the context of the mapping task.
	 */
	void (*event_mapped)		(struct perf_event *event, struct mm_struct *mm); /* optional */
	void (*event_unmapped)		(struct perf_event *event, struct mm_struct *mm); /* optional */

	/*
	 * Flags for ->add()/->del()/ ->start()/->stop(). There are
	 * matching hw_perf_event::state flags.
	 */
#define PERF_EF_START	0x01		/* start the counter when adding    */
#define PERF_EF_RELOAD	0x02		/* reload the counter when starting */
#define PERF_EF_UPDATE	0x04		/* update the counter when stopping */

	/*
	 * Adds/Removes a counter to/from the PMU, can be done inside a
	 * transaction, see the ->*_txn() methods.
	 *
	 * The add/del callbacks will reserve all hardware resources required
	 * to service the event, this includes any counter constraint
	 * scheduling etc.
	 *
	 * Called with IRQs disabled and the PMU disabled on the CPU the event
	 * is on.
	 *
	 * ->add() called without PERF_EF_START should result in the same state
	 *  as ->add() followed by ->stop().
	 *
	 * ->del() must always PERF_EF_UPDATE stop an event. If it calls
	 *  ->stop() that must deal with already being stopped without
	 *  PERF_EF_UPDATE.
	 */
	int  (*add)			(struct perf_event *event, int flags);
	void (*del)			(struct perf_event *event, int flags);

	/*
	 * Starts/Stops a counter present on the PMU.
	 *
	 * The PMI handler should stop the counter when perf_event_overflow()
	 * returns !0. ->start() will be used to continue.
	 *
	 * Also used to change the sample period.
	 *
	 * Called with IRQs disabled and the PMU disabled on the CPU the event
	 * is on -- will be called from NMI context with the PMU generates
	 * NMIs.
	 *
	 * ->stop() with PERF_EF_UPDATE will read the counter and update
	 *  period/count values like ->read() would.
	 *
	 * ->start() with PERF_EF_RELOAD will reprogram the counter
	 *  value, must be preceded by a ->stop() with PERF_EF_UPDATE.
	 */
	void (*start)			(struct perf_event *event, int flags);
	void (*stop)			(struct perf_event *event, int flags);

	/*
	 * Updates the counter value of the event.
	 *
	 * For sampling capable PMUs this will also update the software period
	 * hw_perf_event::period_left field.
	 */
	void (*read)			(struct perf_event *event);

	/*
	 * Group events scheduling is treated as a transaction, add
	 * group events as a whole and perform one schedulability test.
	 * If the test fails, roll back the whole group
	 *
	 * Start the transaction, after this ->add() doesn't need to
	 * do schedulability tests.
	 *
	 * Optional.
	 */
	void (*start_txn)		(struct pmu *pmu, unsigned int txn_flags);
	/*
	 * If ->start_txn() disabled the ->add() schedulability test
	 * then ->commit_txn() is required to perform one. On success
	 * the transaction is closed. On error the transaction is kept
	 * open until ->cancel_txn() is called.
	 *
	 * Optional.
	 */
	int  (*commit_txn)		(struct pmu *pmu);
	/*
	 * Will cancel the transaction, assumes ->del() is called
	 * for each successful ->add() during the transaction.
	 *
	 * Optional.
	 */
	void (*cancel_txn)		(struct pmu *pmu);

	/*
	 * Will return the value for perf_event_mmap_page::index for this event,
	 * if no implementation is provided it will default to: event->hw.idx + 1.
	 */
	int (*event_idx)		(struct perf_event *event); /*optional */

	/*
	 * context-switches callback
	 */
	void (*sched_task)		(struct perf_event_context *ctx,
					bool sched_in);

	/*
	 * Kmem cache of PMU specific data
	 */
	struct kmem_cache		*task_ctx_cache;

	/*
	 * PMU specific parts of task perf event context (i.e. ctx->task_ctx_data)
	 * can be synchronized using this function. See Intel LBR callstack support
	 * implementation and Perf core context switch handling callbacks for usage
	 * examples.
	 */
	void (*swap_task_ctx)		(struct perf_event_context *prev,
					 struct perf_event_context *next);
					/* optional */

	/*
	 * Set up pmu-private data structures for an AUX area
	 */
	void *(*setup_aux)		(struct perf_event *event, void **pages,
					 int nr_pages, bool overwrite);
					/* optional */

	/*
	 * Free pmu-private AUX data structures
	 */
	void (*free_aux)		(void *aux); /* optional */

	/*
	 * Take a snapshot of the AUX buffer without touching the event
	 * state, so that preempting ->start()/->stop() callbacks does
	 * not interfere with their logic. Called in PMI context.
	 *
	 * Returns the size of AUX data copied to the output handle.
	 *
	 * Optional.
	 */
	long (*snapshot_aux)		(struct perf_event *event,
					 struct perf_output_handle *handle,
					 unsigned long size);

	/*
	 * Validate address range filters: make sure the HW supports the
	 * requested configuration and number of filters; return 0 if the
	 * supplied filters are valid, -errno otherwise.
	 *
	 * Runs in the context of the ioctl()ing process and is not serialized
	 * with the rest of the PMU callbacks.
	 */
	int (*addr_filters_validate)	(struct list_head *filters);
					/* optional */

	/*
	 * Synchronize address range filter configuration:
	 * translate hw-agnostic filters into hardware configuration in
	 * event::hw::addr_filters.
	 *
	 * Runs as a part of filter sync sequence that is done in ->start()
	 * callback by calling perf_event_addr_filters_sync().
	 *
	 * May (and should) traverse event::addr_filters::list, for which its
	 * caller provides necessary serialization.
	 */
	void (*addr_filters_sync)	(struct perf_event *event);
					/* optional */

	/*
	 * Check if event can be used for aux_output purposes for
	 * events of this PMU.
	 *
	 * Runs from perf_event_open(). Should return 0 for "no match"
	 * or non-zero for "match".
	 */
	int (*aux_output_match)		(struct perf_event *event);
					/* optional */

	/*
	 * Filter events for PMU-specific reasons.
	 */
	int (*filter_match)		(struct perf_event *event); /* optional */

	/*
	 * Check period value for PERF_EVENT_IOC_PERIOD ioctl.
	 */
	int (*check_period)		(struct perf_event *event, u64 value); /* optional */
};

#endif /* _LINUX_PERF_EVENT_TYPES_H */
