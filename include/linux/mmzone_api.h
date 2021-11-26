/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMZONE_API_H
#define _LINUX_MMZONE_API_H

#ifndef __ASSEMBLY__

#include <linux/mmzone_types.h>

#ifndef __GENERATING_BOUNDS_H

#include <linux/spinlock_types.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <linux/page-flags-layout.h>
#include <linux/atomic_api.h>
#include <linux/math.h>
#include <asm/cpufeature.h>
#include <linux/mm_types.h>
#include <linux/gfp_types.h>
#include <linux/page-flags.h>
#include <linux/local_lock.h>
#include <asm/page.h>

#ifdef CONFIG_CMA
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#  define is_migrate_cma_page(_page) (get_pageblock_migratetype(_page) == MIGRATE_CMA)
#else
#  define is_migrate_cma(migratetype) false
#  define is_migrate_cma_page(_page) false
#endif

static inline bool is_migrate_movable(int mt)
{
	return is_migrate_cma(mt) || mt == MIGRATE_MOVABLE;
}

#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page), MIGRATETYPE_MASK)

static inline struct page *get_page_from_free_area(struct free_area *area,
					    int migratetype)
{
	return list_first_entry_or_null(&area->free_list[migratetype],
					struct page, lru);
}

static inline bool free_area_empty(struct free_area *area, int migratetype)
{
	return list_empty(&area->free_list[migratetype]);
}

#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)

#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)

static inline bool is_file_lru(enum lru_list lru)
{
	return (lru == LRU_INACTIVE_FILE || lru == LRU_ACTIVE_FILE);
}

static inline bool is_active_lru(enum lru_list lru)
{
	return (lru == LRU_ACTIVE_ANON || lru == LRU_ACTIVE_FILE);
}

static inline unsigned long zone_managed_pages(struct zone *zone)
{
	return (unsigned long)atomic_long_read(&zone->managed_pages);
}

static inline unsigned long zone_cma_pages(struct zone *zone)
{
#ifdef CONFIG_CMA
	return zone->cma_pages;
#else
	return 0;
#endif
}

static inline unsigned long zone_end_pfn(const struct zone *zone)
{
	return zone->zone_start_pfn + zone->spanned_pages;
}

static inline bool zone_spans_pfn(const struct zone *zone, unsigned long pfn)
{
	return zone->zone_start_pfn <= pfn && pfn < zone_end_pfn(zone);
}

static inline bool zone_is_initialized(struct zone *zone)
{
	return zone->initialized;
}

static inline bool zone_is_empty(struct zone *zone)
{
	return zone->spanned_pages == 0;
}

/*
 * Return true if [start_pfn, start_pfn + nr_pages) range has a non-empty
 * intersection with the given zone
 */
static inline bool zone_intersects(struct zone *zone,
		unsigned long start_pfn, unsigned long nr_pages)
{
	if (zone_is_empty(zone))
		return false;
	if (start_pfn >= zone_end_pfn(zone) ||
	    start_pfn + nr_pages <= zone->zone_start_pfn)
		return false;

	return true;
}

static inline unsigned long pgdat_end_pfn(pg_data_t *pgdat)
{
	return pgdat->node_start_pfn + pgdat->node_spanned_pages;
}

static inline bool pgdat_is_empty(pg_data_t *pgdat)
{
	return !pgdat->node_start_pfn && !pgdat->node_spanned_pages;
}

void build_all_zonelists(pg_data_t *pgdat);
void wakeup_kswapd(struct zone *zone, gfp_t gfp_mask, int order,
		   enum zone_type highest_zoneidx);
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
			 int highest_zoneidx, unsigned int alloc_flags,
			 long free_pages);
bool zone_watermark_ok(struct zone *z, unsigned int order,
		unsigned long mark, int highest_zoneidx,
		unsigned int alloc_flags);
bool zone_watermark_ok_safe(struct zone *z, unsigned int order,
		unsigned long mark, int highest_zoneidx);
extern void init_currently_empty_zone(struct zone *zone, unsigned long start_pfn,
				     unsigned long size);

extern void lruvec_init(struct lruvec *lruvec);

static inline struct pglist_data *lruvec_pgdat(struct lruvec *lruvec)
{
#ifdef CONFIG_MEMCG
	return lruvec->pgdat;
#else
	return container_of(lruvec, struct pglist_data, __lruvec);
#endif
}

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
int local_memory_node(int node_id);
#else
static inline int local_memory_node(int node_id) { return node_id; };
#endif

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

#ifdef CONFIG_ZONE_DEVICE
static inline bool zone_is_zone_device(struct zone *zone)
{
	return zone_idx(zone) == ZONE_DEVICE;
}
#else
static inline bool zone_is_zone_device(struct zone *zone)
{
	return false;
}
#endif

/*
 * Returns true if a zone has pages managed by the buddy allocator.
 * All the reclaim decisions have to use this function rather than
 * populated_zone(). If the whole zone is reserved then we can easily
 * end up with populated_zone() && !managed_zone().
 */
static inline bool managed_zone(struct zone *zone)
{
	return zone_managed_pages(zone);
}

/* Returns true if a zone has memory */
static inline bool populated_zone(struct zone *zone)
{
	return zone->present_pages;
}

#ifdef CONFIG_NUMA
static inline int zone_to_nid(struct zone *zone)
{
	return zone->node;
}

static inline void zone_set_nid(struct zone *zone, int nid)
{
	zone->node = nid;
}
#else
static inline int zone_to_nid(struct zone *zone)
{
	return 0;
}

static inline void zone_set_nid(struct zone *zone, int nid) {}
#endif

static inline int is_highmem_idx(enum zone_type idx)
{
#ifdef CONFIG_HIGHMEM
	return (idx == ZONE_HIGHMEM ||
		(idx == ZONE_MOVABLE && movable_zone == ZONE_HIGHMEM));
#else
	return 0;
#endif
}

#ifdef CONFIG_ZONE_DMA
bool has_managed_dma(void);
#else
static inline bool has_managed_dma(void)
{
	return false;
}
#endif

/**
 * is_highmem - helper function to quickly check if a struct zone is a
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone: pointer to struct zone variable
 * Return: 1 for a highmem zone, 0 otherwise
 */
static inline int is_highmem(struct zone *zone)
{
#ifdef CONFIG_HIGHMEM
	return is_highmem_idx(zone_idx(zone));
#else
	return 0;
#endif
}

/* These two functions are used to setup the per zone pages min values */
struct ctl_table;

int min_free_kbytes_sysctl_handler(struct ctl_table *, int, void *, size_t *,
		loff_t *);
int watermark_scale_factor_sysctl_handler(struct ctl_table *, int, void *,
		size_t *, loff_t *);
extern int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES];
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int, void *,
		size_t *, loff_t *);
int percpu_pagelist_high_fraction_sysctl_handler(struct ctl_table *, int,
		void *, size_t *, loff_t *);
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *, int,
		void *, size_t *, loff_t *);
int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *, int,
		void *, size_t *, loff_t *);
int numa_zonelist_order_handler(struct ctl_table *, int,
		void *, size_t *, loff_t *);
extern int percpu_pagelist_high_fraction;
extern char numa_zonelist_order[];
#define NUMA_ZONELIST_ORDER_LEN	16

#ifdef CONFIG_NUMA
# include <asm/mmzone.h>
#endif

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);

/**
 * for_each_online_pgdat - helper macro to iterate over all online nodes
 * @pgdat: pointer to a pg_data_t variable
 */
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone: pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))

#define for_each_populated_zone(zone)		        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))			\
		if (!populated_zone(zone))		\
			; /* do nothing */		\
		else

static inline struct zone *zonelist_zone(struct zoneref *zoneref)
{
	return zoneref->zone;
}

static inline int zonelist_zone_idx(struct zoneref *zoneref)
{
	return zoneref->zone_idx;
}

static inline int zonelist_node_idx(struct zoneref *zoneref)
{
	return zone_to_nid(zoneref->zone);
}

struct zoneref *__next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes);

/**
 * next_zones_zonelist - Returns the next zone at or below highest_zoneidx within the allowed nodemask using a cursor within a zonelist as a starting point
 * @z: The cursor used as a starting point for the search
 * @highest_zoneidx: The zone index of the highest zone to return
 * @nodes: An optional nodemask to filter the zonelist with
 *
 * This function returns the next zone at or below a given zone index that is
 * within the allowed nodemask using a cursor as the starting point for the
 * search. The zoneref returned is a cursor that represents the current zone
 * being examined. It should be advanced by one before calling
 * next_zones_zonelist again.
 *
 * Return: the next zone at or below highest_zoneidx within the allowed
 * nodemask using a cursor within a zonelist as a starting point
 */
static __always_inline struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	if (likely(!nodes && zonelist_zone_idx(z) <= highest_zoneidx))
		return z;
	return __next_zones_zonelist(z, highest_zoneidx, nodes);
}

/**
 * first_zones_zonelist - Returns the first zone at or below highest_zoneidx within the allowed nodemask in a zonelist
 * @zonelist: The zonelist to search for a suitable zone
 * @highest_zoneidx: The zone index of the highest zone to return
 * @nodes: An optional nodemask to filter the zonelist with
 *
 * This function returns the first zone at or below a given zone index that is
 * within the allowed nodemask. The zoneref returned is a cursor that can be
 * used to iterate the zonelist with next_zones_zonelist by advancing it by
 * one before calling.
 *
 * When no eligible zone is found, zoneref->zone is NULL (zoneref itself is
 * never NULL). This may happen either genuinely, or due to concurrent nodemask
 * update due to cpuset modification.
 *
 * Return: Zoneref pointer for the first suitable zone found
 */
static inline struct zoneref *first_zones_zonelist(struct zonelist *zonelist,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes)
{
	return next_zones_zonelist(zonelist->_zonerefs,
							highest_zoneidx, nodes);
}

/**
 * for_each_zone_zonelist_nodemask - helper macro to iterate over valid zones in a zonelist at or below a given zone index and within a nodemask
 * @zone: The current zone in the iterator
 * @z: The current pointer within zonelist->_zonerefs being iterated
 * @zlist: The zonelist being iterated
 * @highidx: The zone index of the highest zone to return
 * @nodemask: Nodemask allowed by the allocator
 *
 * This iterator iterates though all zones at or below a given zone index and
 * within a given nodemask
 */
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (z = first_zones_zonelist(zlist, highidx, nodemask), zone = zonelist_zone(z);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))

#define for_next_zone_zonelist_nodemask(zone, z, highidx, nodemask) \
	for (zone = z->zone;	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))


/**
 * for_each_zone_zonelist - helper macro to iterate over valid zones in a zonelist at or below a given zone index
 * @zone: The current zone in the iterator
 * @z: The current pointer within zonelist->zones being iterated
 * @zlist: The zonelist being iterated
 * @highidx: The zone index of the highest zone to return
 *
 * This iterator iterates though all zones at or below a given zone index.
 */
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
	for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)

/* Whether the 'nodes' are all movable nodes */
static inline bool movable_only_nodes(nodemask_t *nodes)
{
	struct zonelist *zonelist;
	struct zoneref *z;
	int nid;

	if (nodes_empty(*nodes))
		return false;

	/*
	 * We can chose arbitrary node from the nodemask to get a
	 * zonelist as they are interlinked. We just need to find
	 * at least one zone that can satisfy kernel allocations.
	 */
	nid = first_node(*nodes);
	zonelist = &NODE_DATA(nid)->node_zonelists[ZONELIST_FALLBACK];
	z = first_zones_zonelist(zonelist, ZONE_NORMAL,	nodes);
	return (!z->zone) ? true : false;
}


#ifdef CONFIG_SPARSEMEM
#include <asm/sparsemem.h>
#endif

#ifdef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

#ifdef CONFIG_SPARSEMEM

/*
 * PA_SECTION_SHIFT		physical address to/from section number
 * PFN_SECTION_SHIFT		pfn to/from section number
 */
#define PA_SECTION_SHIFT	(SECTION_SIZE_BITS)
#define PFN_SECTION_SHIFT	(SECTION_SIZE_BITS - PAGE_SHIFT)

#define NR_MEM_SECTIONS		(1UL << SECTIONS_SHIFT)

#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_SECTION_MASK	(~(PAGES_PER_SECTION-1))

#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)

#if (MAX_ORDER - 1 + PAGE_SHIFT) > SECTION_SIZE_BITS
#error Allocator MAX_ORDER exceeds SECTION_SIZE
#endif

static inline unsigned long pfn_to_section_nr(unsigned long pfn)
{
	return pfn >> PFN_SECTION_SHIFT;
}
static inline unsigned long section_nr_to_pfn(unsigned long sec)
{
	return sec << PFN_SECTION_SHIFT;
}

#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)

#define SUBSECTION_SHIFT 21
#define SUBSECTION_SIZE (1UL << SUBSECTION_SHIFT)

#define PFN_SUBSECTION_SHIFT (SUBSECTION_SHIFT - PAGE_SHIFT)
#define PAGES_PER_SUBSECTION (1UL << PFN_SUBSECTION_SHIFT)
#define PAGE_SUBSECTION_MASK (~(PAGES_PER_SUBSECTION-1))

#if SUBSECTION_SHIFT > SECTION_SIZE_BITS
#error Subsection size exceeds section size
#else
#define SUBSECTIONS_PER_SECTION (1UL << (SECTION_SIZE_BITS - SUBSECTION_SHIFT))
#endif

#define SUBSECTION_ALIGN_UP(pfn) ALIGN((pfn), PAGES_PER_SUBSECTION)
#define SUBSECTION_ALIGN_DOWN(pfn) ((pfn) & PAGE_SUBSECTION_MASK)

struct mem_section_usage {
#ifdef CONFIG_SPARSEMEM_VMEMMAP
	DECLARE_BITMAP(subsection_map, SUBSECTIONS_PER_SECTION);
#endif
	/* See declaration of similar field in struct zone */
	unsigned long pageblock_flags[0];
};

void subsection_map_init(unsigned long pfn, unsigned long nr_pages);

struct page;
struct page_ext;
struct mem_section {
	/*
	 * This is, logically, a pointer to an array of struct
	 * pages.  However, it is stored with some other magic.
	 * (see sparse.c::sparse_init_one_section())
	 *
	 * Additionally during early boot we encode node id of
	 * the location of the section here to guide allocation.
	 * (see sparse.c::memory_present())
	 *
	 * Making it a UL at least makes someone do a cast
	 * before using it wrong.
	 */
	unsigned long section_mem_map;

	struct mem_section_usage *usage;
#ifdef CONFIG_PAGE_EXTENSION
	/*
	 * If SPARSEMEM, pgdat doesn't have page_ext pointer. We use
	 * section. (see page_ext.h about this.)
	 */
	struct page_ext *page_ext;
	unsigned long pad;
#endif
	/*
	 * WARNING: mem_section must be a power-of-2 in size for the
	 * calculation and use of SECTION_ROOT_MASK to make sense.
	 */
};

#ifdef CONFIG_SPARSEMEM_EXTREME
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
#define SECTIONS_PER_ROOT	1
#endif

#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define NR_SECTION_ROOTS	DIV_ROUND_UP(NR_MEM_SECTIONS, SECTIONS_PER_ROOT)
#define SECTION_ROOT_MASK	(SECTIONS_PER_ROOT - 1)

#ifdef CONFIG_SPARSEMEM_EXTREME
extern struct mem_section **mem_section;
#else
extern struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT];
#endif

static inline unsigned long *section_to_usemap(struct mem_section *ms)
{
	return ms->usage->pageblock_flags;
}

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
#ifdef CONFIG_SPARSEMEM_EXTREME
	if (!mem_section)
		return NULL;
#endif
	if (!mem_section[SECTION_NR_TO_ROOT(nr)])
		return NULL;
	return &mem_section[SECTION_NR_TO_ROOT(nr)][nr & SECTION_ROOT_MASK];
}
extern size_t mem_section_usage_size(void);

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  The pointer is calculated
 * as mem_map - section_nr_to_pfn(pnum).  The result is
 * aligned to the minimum alignment of the two values:
 *   1. All mem_map arrays are page-aligned.
 *   2. section_nr_to_pfn() always clears PFN_SECTION_SHIFT
 *      lowest bits.  PFN_SECTION_SHIFT is arch-specific
 *      (equal SECTION_SIZE_BITS - PAGE_SHIFT), and the
 *      worst combination is powerpc with 256k pages,
 *      which results in PFN_SECTION_SHIFT equal 6.
 * To sum it up, at least 6 bits are available.
 */
#define SECTION_MARKED_PRESENT		(1UL<<0)
#define SECTION_HAS_MEM_MAP		(1UL<<1)
#define SECTION_IS_ONLINE		(1UL<<2)
#define SECTION_IS_EARLY		(1UL<<3)
#define SECTION_TAINT_ZONE_DEVICE	(1UL<<4)
#define SECTION_MAP_LAST_BIT		(1UL<<5)
#define SECTION_MAP_MASK		(~(SECTION_MAP_LAST_BIT-1))
#define SECTION_NID_SHIFT		6

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
	unsigned long map = section->section_mem_map;
	map &= SECTION_MAP_MASK;
	return (struct page *)map;
}

static inline int present_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_MARKED_PRESENT));
}

static inline int present_section_nr(unsigned long nr)
{
	return present_section(__nr_to_section(nr));
}
static inline int valid_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_HAS_MEM_MAP));
}

static inline int early_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_IS_EARLY));
}

static inline int valid_section_nr(unsigned long nr)
{
	return valid_section(__nr_to_section(nr));
}

static inline int online_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_IS_ONLINE));
}

static inline int online_device_section(struct mem_section *section)
{
	unsigned long flags = SECTION_IS_ONLINE | SECTION_TAINT_ZONE_DEVICE;

	return section && ((section->section_mem_map & flags) == flags);
}

static inline int online_section_nr(unsigned long nr)
{
	return online_section(__nr_to_section(nr));
}

#ifdef CONFIG_MEMORY_HOTPLUG
void online_mem_sections(unsigned long start_pfn, unsigned long end_pfn);
void offline_mem_sections(unsigned long start_pfn, unsigned long end_pfn);
#endif

static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
	return __nr_to_section(pfn_to_section_nr(pfn));
}

extern unsigned long __highest_present_section_nr;

static inline int subsection_map_index(unsigned long pfn)
{
	return (pfn & ~(PAGE_SECTION_MASK)) / PAGES_PER_SUBSECTION;
}

#ifdef CONFIG_SPARSEMEM_VMEMMAP
static inline int pfn_section_valid(struct mem_section *ms, unsigned long pfn)
{
	int idx = subsection_map_index(pfn);

	return test_bit(idx, ms->usage->subsection_map);
}
#else
static inline int pfn_section_valid(struct mem_section *ms, unsigned long pfn)
{
	return 1;
}
#endif

#ifndef CONFIG_HAVE_ARCH_PFN_VALID
/**
 * pfn_valid - check if there is a valid memory map entry for a PFN
 * @pfn: the page frame number to check
 *
 * Check if there is a valid memory map entry aka struct page for the @pfn.
 * Note, that availability of the memory map entry does not imply that
 * there is actual usable memory at that @pfn. The struct page may
 * represent a hole or an unusable page frame.
 *
 * Return: 1 for PFNs that have memory map entries and 0 otherwise
 */
static inline int pfn_valid(unsigned long pfn)
{
	struct mem_section *ms;

	/*
	 * Ensure the upper PAGE_SHIFT bits are clear in the
	 * pfn. Else it might lead to false positives when
	 * some of the upper bits are set, but the lower bits
	 * match a valid pfn.
	 */
	if (PHYS_PFN(PFN_PHYS(pfn)) != pfn)
		return 0;

	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	ms = __pfn_to_section(pfn);
	if (!valid_section(ms))
		return 0;
	/*
	 * Traditionally early sections always returned pfn_valid() for
	 * the entire section-sized span.
	 */
	return early_section(ms) || pfn_section_valid(ms, pfn);
}
#endif

static inline int pfn_in_present_section(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return present_section(__pfn_to_section(pfn));
}

static inline unsigned long next_present_section_nr(unsigned long section_nr)
{
	while (++section_nr <= __highest_present_section_nr) {
		if (present_section_nr(section_nr))
			return section_nr;
	}

	return -1;
}

/*
 * These are _only_ used during initialisation, therefore they
 * can use __initdata ...  They could have names to indicate
 * this restriction.
 */
#ifdef CONFIG_NUMA
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#else
#define pfn_to_nid(pfn)		(0)
#endif

void sparse_init(void);
#else
#define sparse_init()	do {} while (0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define pfn_in_present_section pfn_valid
#define subsection_map_init(_pfn, _nr_pages) do {} while (0)
#endif /* CONFIG_SPARSEMEM */

#endif /* !__GENERATING_BOUNDS.H */
#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_MMZONE_API_H */
