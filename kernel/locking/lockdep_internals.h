/*
 * kernel/lockdep_internals.h
 *
 * Runtime locking correctness validator
 *
 * lockdep subsystem internal functions and variables.
 */

/*
 * Lock-class usage-state bits:
 */
enum lock_usage_bit {
#define LOCKDEP_STATE(__STATE)		\
	LOCK_USED_IN_##__STATE,		\
	LOCK_USED_IN_##__STATE##_READ,	\
	LOCK_ENABLED_##__STATE,		\
	LOCK_ENABLED_##__STATE##_READ,
#include "lockdep_states.h"
#undef LOCKDEP_STATE
	LOCK_USED,
	LOCK_USAGE_STATES
};

/*
 * Usage-state bitmasks:
 */
#define __LOCKF(__STATE)	LOCKF_##__STATE = (1 << LOCK_##__STATE),

enum {
#define LOCKDEP_STATE(__STATE)						\
	__LOCKF(USED_IN_##__STATE)					\
	__LOCKF(USED_IN_##__STATE##_READ)				\
	__LOCKF(ENABLED_##__STATE)					\
	__LOCKF(ENABLED_##__STATE##_READ)
#include "lockdep_states.h"
#undef LOCKDEP_STATE
	__LOCKF(USED)
};

#define LOCKF_ENABLED_IRQ (LOCKF_ENABLED_HARDIRQ | LOCKF_ENABLED_SOFTIRQ)
#define LOCKF_USED_IN_IRQ (LOCKF_USED_IN_HARDIRQ | LOCKF_USED_IN_SOFTIRQ)

#define LOCKF_ENABLED_IRQ_READ \
		(LOCKF_ENABLED_HARDIRQ_READ | LOCKF_ENABLED_SOFTIRQ_READ)
#define LOCKF_USED_IN_IRQ_READ \
		(LOCKF_USED_IN_HARDIRQ_READ | LOCKF_USED_IN_SOFTIRQ_READ)

/*
 * MAX_LOCKDEP_ENTRIES is the maximum number of lock dependencies
 * we track.
 *
 * We use the per-lock dependency maps in two ways: we grow it by adding
 * every to-be-taken lock to all currently held lock's own dependency
 * table (if it's not there yet), and we check it for lock order
 * conflicts and deadlocks.
 */
#define MAX_LOCKDEP_ENTRIES	32768UL

#define MAX_LOCKDEP_CHAINS_BITS	16
#define MAX_LOCKDEP_CHAINS	(1UL << MAX_LOCKDEP_CHAINS_BITS)

#define MAX_LOCKDEP_CHAIN_HLOCKS (MAX_LOCKDEP_CHAINS*5)

/*
 * Stack-trace: tightly packed array of stack backtrace
 * addresses. Protected by the hash_lock.
 */
#define MAX_STACK_TRACE_ENTRIES	524288UL

extern struct list_head all_lock_classes;
extern struct lock_chain lock_chains[];

#define LOCK_USAGE_CHARS (1+LOCK_USAGE_STATES/2)

extern void get_usage_chars(struct lock_class *class,
			    char usage[LOCK_USAGE_CHARS]);

extern const char * __get_key_name(struct lockdep_subclass_key *key, char *str);

struct lock_class *lock_chain_get_class(struct lock_chain *chain, int i);

extern unsigned long nr_lock_classes;
extern unsigned long nr_list_entries;
extern unsigned long nr_lock_chains;
extern int nr_chain_hlocks;
extern unsigned long nr_stack_trace_entries;

extern unsigned int nr_hardirq_chains;
extern unsigned int nr_softirq_chains;
extern unsigned int nr_process_chains;
extern unsigned int max_lockdep_depth;
extern unsigned int max_recursion_depth;

extern unsigned int max_bfs_queue_depth;

#ifdef CONFIG_PROVE_LOCKING
extern unsigned long lockdep_count_forward_deps(struct lock_class *);
extern unsigned long lockdep_count_backward_deps(struct lock_class *);
#else
static inline unsigned long
lockdep_count_forward_deps(struct lock_class *class)
{
	return 0;
}
static inline unsigned long
lockdep_count_backward_deps(struct lock_class *class)
{
	return 0;
}
#endif

#ifdef CONFIG_DEBUG_LOCKDEP

#include <asm/local.h>
/*
 * Various lockdep statistics.
 * We want them per cpu as they are often accessed in fast path
 * and we want to avoid too much cache bouncing.
 */
struct lockdep_stats {
	int	chain_lookup_hits;
	int	chain_lookup_misses;
	int	hardirqs_on_events;
	int	hardirqs_off_events;
	int	redundant_hardirqs_on;
	int	redundant_hardirqs_off;
	int	softirqs_on_events;
	int	softirqs_off_events;
	int	redundant_softirqs_on;
	int	redundant_softirqs_off;
	int	nr_unused_locks;
	int	nr_cyclic_checks;
	int	nr_cyclic_check_recursions;
	int	nr_find_usage_forwards_checks;
	int	nr_find_usage_forwards_recursions;
	int	nr_find_usage_backwards_checks;
	int	nr_find_usage_backwards_recursions;
};

DECLARE_PER_CPU(struct lockdep_stats, lockdep_stats);

#define __debug_atomic_inc(ptr)					\
	this_cpu_inc(lockdep_stats.ptr);

#define debug_atomic_inc(ptr)			{		\
	WARN_ON_ONCE(!irqs_disabled());				\
	__this_cpu_inc(lockdep_stats.ptr);			\
}

#define debug_atomic_dec(ptr)			{		\
	WARN_ON_ONCE(!irqs_disabled());				\
	__this_cpu_dec(lockdep_stats.ptr);			\
}

#define debug_atomic_read(ptr)		({				\
	struct lockdep_stats *__cpu_lockdep_stats;			\
	unsigned long long __total = 0;					\
	int __cpu;							\
	for_each_possible_cpu(__cpu) {					\
		__cpu_lockdep_stats = &per_cpu(lockdep_stats, __cpu);	\
		__total += __cpu_lockdep_stats->ptr;			\
	}								\
	__total;							\
})
#else
# define __debug_atomic_inc(ptr)	do { } while (0)
# define debug_atomic_inc(ptr)		do { } while (0)
# define debug_atomic_dec(ptr)		do { } while (0)
# define debug_atomic_read(ptr)		0
#endif

#ifdef CONFIG_LOCKED_ACCESS
/*
 * A chain of lock acquisitions, keyed by the hash sum of all the
 * instruction positions of lock acquisitions
 */
struct acqchain {
	u8				irq_context;
	s8				depth;
	s16				base;
	/* Entry in hash table */
	struct list_head		entry;
	u64				chain_key;
	/* List of data accesses that happen after this chain */
	struct list_head		accesses;
};

#define iterate_acqchain_key(key, ip) \
	(((key) << MAX_LOCKDEP_KEYS_BITS) ^ \
	((key) >> (64 - MAX_LOCKDEP_KEYS_BITS)) ^ \
	(ip))

#define MAX_ACQCHAINS_BITS	16
#define MAX_ACQCHAINS		(1UL << MAX_ACQCHAINS_BITS)
#define MAX_ACQCHAIN_HLOCKS	(MAX_ACQCHAINS * 5)

#define ACQCHAIN_HASH_BITS	(MAX_ACQCHAINS_BITS-1)
#define ACQCHAIN_HASH_SIZE	(1UL << ACQCHAIN_HASH_BITS)
#define __acqchainhashfn(chain)	hash_long(chain, ACQCHAIN_HASH_BITS)
#define acqchainhashentry(lad, chain) \
	(lad->acqchain_hashtable + __acqchainhashfn((chain)))

#define MAX_LOCKED_ACCESS_STRUCTS	(1UL << 16)

/* Records of data accesses in LOCKED_ACCESS */
struct locked_access_struct {
	struct list_head		list;
	struct locked_access_location	*loc;
	int				type;
};

/*
 * locked_access_class represent a group of critical sections and related data
 * accesses. Locked access class should be only defined statically, and the
 * address of a locked_access_class is used as the 'key' of a locked access
 * class.
 */
struct locked_access_class {
	const char                   *name;
	/* Hash table of acqchains, for lookup */
	struct list_head             acqchain_hashtable[ACQCHAIN_HASH_SIZE];
	/* Storage of acqchains, for allocation */
	struct acqchain	             acqchains[MAX_ACQCHAINS];
	long                         nr_acqchains;
	/* Storage of acquired IPs of acqchains, for allocation */
	unsigned long                acqchain_hlocks[MAX_ACQCHAIN_HLOCKS];
	long                         nr_acqchain_hlocks;
	/* Storage of data accesses, for allocation */
	struct locked_access_struct  access_structs[MAX_LOCKED_ACCESS_STRUCTS];
	long                         nr_access_structs;
	arch_spinlock_t              lock;
	int                          initialized;
};

#define INIT_LOCKED_ACCESS_DATA(_name) \
	{ \
		.name = #_name, \
		.lock = __ARCH_SPIN_LOCK_UNLOCKED, \
		.initialized = 0, \
		.nr_acqchains = 0, \
		.nr_acqchain_hlocks = 0,\
		.nr_access_structs = 0, \
	}

extern int create_laclass_proc(const char *name,
			   struct locked_access_class *laclass);

#define DEFINE_CREATE_LACLASS_PROC(name) \
static int __init ___create_##name##_laclass_proc(void) \
{ \
	return create_laclass_proc(#name, &name##_laclass); \
} \
late_initcall(___create_##name##_laclass_proc)

/* Define a Locked Access Class and create its proc file */
#define DEFINE_LACLASS(name) \
	struct locked_access_class name##_laclass = \
			INIT_LOCKED_ACCESS_DATA(name); \
	EXPORT_SYMBOL(name##_laclass); \
	DEFINE_CREATE_LACLASS_PROC(name)
#endif /* CONFIG_LOCKED_ACCESS */
