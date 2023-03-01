#ifndef _KERNEL_TIME_MIGRATION_H
#define _KERNEL_TIME_MIGRATION_H

/* Per group capacity. Must be a power of 2! */
#define TMIGR_CHILDS_PER_GROUP 8

/**
 * struct tmigr_event - a timer event associated to a CPU
 * @nextevt:	The node to enqueue an event in the parent group queue
 * @cpu:	The CPU to which this event belongs
 * @ignore:	Hint whether the event could be ignored; it is set when
 *		CPU or group is active;
 */
struct tmigr_event {
	struct timerqueue_node	nextevt;
	unsigned int		cpu;
	int			ignore;
};

/**
 * struct tmigr_group - timer migration hierarchy group
 * @lock:		Lock protecting the event information
 * @cpus:		Array with CPUs which are member of group; required for
 *			sibling CPUs; used only when level == 0
 * @parent:		Pointer to parent group
 * @list:		List head that is added to per level tmigr_level_list
 * @level:		Hierarchy level of group
 * @numa_node:		Is set to numa node when level < tmigr_crossnode_level;
 *			otherwise it is set to NUMA_NO_NODE; Required for setup
 *			only
 * @num_childs:		Counter of group childs; Required for setup only
 * @num_cores:		Counter of cores per group; Required for setup only when
 *			level == 0 and siblings exist
 * @migr_state:		State of group (see struct tmigr_state)
 * @childmask:		childmask of group in parent group; is set during setup
 *			never changed; could be read lockless
 * @events:		Timer queue for child events queued in the group
 * @groupevt:		Next event of group; it is only reliable when group is
 *			!active (ignore bit is set when group is active)
 * @next_expiry:	Base monotonic expiry time of next event of group;
 *			Used for racy lockless check whether remote expiry is
 *			required; it is always reliable
 */
struct tmigr_group {
	raw_spinlock_t		lock;
	unsigned int		cpus[TMIGR_CHILDS_PER_GROUP];
	struct tmigr_group	*parent;
	struct list_head	list;
	unsigned int		level;
	unsigned int		numa_node;
	unsigned int		num_childs;
	unsigned int		num_cores;
	atomic_t		*migr_state;
	u32			childmask;
	struct timerqueue_head	events;
	struct tmigr_event	groupevt;
	u64			next_expiry;
};

/**
 * struct tmigr_cpu - timer migration per CPU group
 * @lock:	Lock protecting tmigr_cpu group information
 * @online:	Indicates wheter CPU is online
 * @idle:	Indicates wheter CPU is idle in timer migration hierarchy
 * @remote:	Is set when timers of CPU are expired remote
 * @tmgroup:	Pointer to parent group
 * @childmask:	childmask of tmigr_cpu in parent group
 * @cpuevt:	CPU event which could be queued into parent group
 * @wakeup:	Stores the first timer when the timer migration hierarchy is
 *		completely idle and remote expiry was done; is returned to
 *		timer code when tmigr_cpu_deactive() is called and group is
 *		idle; afterwards a reset to KTIME_MAX is required;
 */
struct tmigr_cpu {
	raw_spinlock_t		lock;
	int			online;
	int			idle;
	int			remote;
	struct tmigr_group	*tmgroup;
	u32			childmask;
	struct tmigr_event	cpuevt;
	u64			wakeup;
};

/**
 * union tmigr_state - state of tmigr_group
 * @state:	Combined version of the state - only used for atomic
 * 		read/cmpxchg function
 * @struct:	Splitted version of the state - only use the struct members to
 *		update information to stay independant of endianess
 */
union tmigr_state {
	u32 state;
	/**
	 * struct - splitted state of tmigr_group
	 * @active:	Contains each childmask bit of active childs
	 * @migrator:	Contains childmask of child which is migrator
	 * @seq:	Seqence number to prevent race when update in child
	 *		group are propagated in wrong order (especially when
	 *		migrator changes are involved)
	 */
	struct {
		u8	active;
		u8	migrator;
		u16	seq;
	} __packed;
};

#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
extern void tmigr_handle_remote(void);
extern int tmigr_requires_handle_remote(void);
extern void tmigr_cpu_activate(void);
extern u64 tmigr_cpu_deactivate(u64 nextevt);
extern void timer_expire_remote(unsigned int cpu);
#else
static inline void tmigr_handle_remote(void) { }
extern inline int tmigr_requires_handle_remote(void) { return 0; }
static inline void tmigr_cpu_activate(void) { }
static inline u64 tmigr_cpu_deactivate(u64 nextevt) { return KTIME_MAX; }
extern inline void timer_expire_remote(unsigned int cpu) { }
#endif

#endif
