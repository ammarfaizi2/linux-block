#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/cpu.h>

#include <linux/blk-mq.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-tag.h"

/*
 * Per-cpu cache entries
 */
struct blk_mq_tag_map {
	unsigned int nr_free;
	unsigned int freelist[];
};

/*
 * Per tagged queue (tag address space) map
 */
struct blk_mq_tags {
	unsigned int nr_tags;
	unsigned int reserved_tags;
	unsigned int batch_move;
	unsigned int max_cache;

	struct {
		spinlock_t lock;
		unsigned int nr_free;
		unsigned int *freelist;
		unsigned int nr_reserved;
		unsigned int *reservelist;
		struct list_head wait;
	} ____cacheline_aligned_in_smp;

	struct blk_mq_tag_map __percpu *free_maps;

	struct blk_mq_cpu_notifier cpu_notifier;
};

struct blk_mq_tag_wait {
	struct list_head list;
	struct task_struct *task;
};

#define DEFINE_TAG_WAIT(name)						\
	struct blk_mq_tag_wait name = {					\
		.list		= LIST_HEAD_INIT((name).list),		\
		.task		= current,				\
	}

static unsigned int move_tags(unsigned int *dst, unsigned int *dst_nr,
			      unsigned int *src, unsigned int *src_nr,
			      unsigned int nr_to_move)
{
	nr_to_move = min(nr_to_move, *src_nr);
	*src_nr -= nr_to_move;
	memcpy(dst + *dst_nr, src + *src_nr, sizeof(int) * nr_to_move);
	*dst_nr += nr_to_move;

	return nr_to_move;
}

static void __wake_waiters(struct blk_mq_tags *tags, unsigned int nr)
{
	while (nr && !list_empty(&tags->wait)) {
		struct blk_mq_tag_wait *waiter;

		waiter = list_entry(tags->wait.next, struct blk_mq_tag_wait,
					list);
		list_del_init(&waiter->list);
		wake_up_process(waiter->task);
		nr--;
	}
}

static void __blk_mq_tag_return(struct blk_mq_tags *tags,
				struct blk_mq_tag_map *map, unsigned int nr)
{
	unsigned int waiters;

	lockdep_assert_held(&tags->lock);

	waiters = move_tags(tags->freelist, &tags->nr_free, map->freelist,
				&map->nr_free, nr);
	if (!list_empty(&tags->wait))
		__wake_waiters(tags, waiters);
}

static void blk_mq_tag_return(struct blk_mq_tags *tags,
			      struct blk_mq_tag_map *map, unsigned int nr)
{
	unsigned long flags;

	spin_lock_irqsave(&tags->lock, flags);
	__blk_mq_tag_return(tags, map, nr);
	spin_unlock_irqrestore(&tags->lock, flags);
}

#if NR_CPUS != 1
static void prune_cache(void *data)
{
	struct blk_mq_tags *tags = data;
	struct blk_mq_tag_map *map;

	map = per_cpu_ptr(tags->free_maps, smp_processor_id());

	spin_lock(&tags->lock);
	__blk_mq_tag_return(tags, map, tags->batch_move);
	spin_unlock(&tags->lock);
}
#endif

static void ipi_local_caches(struct blk_mq_tags *tags, unsigned int this_cpu)
{
#if NR_CPUS != 1
	cpumask_var_t ipi_mask;
	unsigned int i, total;

	/*
	 * We could per-cpu cache this things, but overhead is probably not
	 * large enough to care about it. If we fail, just punt to doing a
	 * prune on all CPUs.
	 */
	if (!alloc_cpumask_var(&ipi_mask, GFP_ATOMIC)) {
		smp_call_function(prune_cache, tags, 0);
		return;
	}

	cpumask_clear(ipi_mask);

	total = 0;
	for_each_online_cpu(i) {
		struct blk_mq_tag_map *map = per_cpu_ptr(tags->free_maps, i);

		if (!map->nr_free)
			continue;

		total += map->nr_free;
		cpumask_set_cpu(i, ipi_mask);

		if (total > tags->batch_move)
			break;
	}

	if (total) {
		preempt_disable();
		smp_call_function_many(ipi_mask, prune_cache, tags, 0);
		preempt_enable();
	}

	free_cpumask_var(ipi_mask);
#endif
}

/*
 * Wait on a free tag, move batch to map when we have it. Returns with
 * local CPU irq flags saved in 'flags'.
 */
static void wait_on_tags(struct blk_mq_tags *tags, struct blk_mq_tag_map **map,
			 unsigned long *flags)
{
	DEFINE_TAG_WAIT(wait);

	do {
		spin_lock_irqsave(&tags->lock, *flags);

		__set_current_state(TASK_UNINTERRUPTIBLE);

		if (list_empty(&wait.list))
			list_add_tail(&wait.list, &tags->wait);

		*map = this_cpu_ptr(tags->free_maps);
		if ((*map)->nr_free || tags->nr_free) {
			if (!(*map)->nr_free) {
				move_tags((*map)->freelist, &(*map)->nr_free,
						tags->freelist, &tags->nr_free,
						tags->batch_move);
			}

			if (!list_empty(&wait.list))
				list_del(&wait.list);

			spin_unlock(&tags->lock);
			break;
		}

		spin_unlock_irqrestore(&tags->lock, *flags);
		ipi_local_caches(tags, raw_smp_processor_id());
		io_schedule();
	} while (1);

	__set_current_state(TASK_RUNNING);
}

void blk_mq_wait_for_tags(struct blk_mq_tags *tags)
{
	struct blk_mq_tag_map *map;
	unsigned long flags;

	ipi_local_caches(tags, raw_smp_processor_id());
	wait_on_tags(tags, &map, &flags);
	local_irq_restore(flags);
}

bool blk_mq_has_free_tags(struct blk_mq_tags *tags)
{
	return !tags || tags->nr_free != 0;
}

static unsigned int __blk_mq_get_tag(struct blk_mq_tags *tags, gfp_t gfp)
{
	struct blk_mq_tag_map *map;
	unsigned int this_cpu;
	unsigned long flags;
	unsigned int tag;

	local_irq_save(flags);
	this_cpu = smp_processor_id();
	map = per_cpu_ptr(tags->free_maps, this_cpu);

	/*
	 * Grab from local per-cpu cache, if we can
	 */
	do {
		if (map->nr_free) {
			map->nr_free--;
			tag = map->freelist[map->nr_free];
			local_irq_restore(flags);
			return tag;
		}

		/*
		 * Grab from device map, if we can
		 */
		if (tags->nr_free) {
			spin_lock(&tags->lock);
			move_tags(map->freelist, &map->nr_free, tags->freelist,
					&tags->nr_free, tags->batch_move);
			spin_unlock(&tags->lock);
			continue;
		}

		local_irq_restore(flags);

		if (!(gfp & __GFP_WAIT))
			break;

		ipi_local_caches(tags, this_cpu);

		/*
		 * All are busy, wait. Returns with irqs disabled again
		 * and potentially new 'map' pointer.
		 */
		wait_on_tags(tags, &map, &flags);
	} while (1);

	return BLK_MQ_TAG_FAIL;
}

static unsigned int __blk_mq_get_reserved_tag(struct blk_mq_tags *tags,
					      gfp_t gfp)
{
	unsigned int tag = BLK_MQ_TAG_FAIL;
	DEFINE_TAG_WAIT(wait);

	if (unlikely(!tags->reserved_tags)) {
		WARN_ON_ONCE(1);
		return BLK_MQ_TAG_FAIL;
	}

	do {
		spin_lock_irq(&tags->lock);
		if (tags->nr_reserved) {
			tags->nr_reserved--;
			tag = tags->reservelist[tags->nr_reserved];
			break;
		}

		if (!(gfp & __GFP_WAIT))
			break;

		__set_current_state(TASK_UNINTERRUPTIBLE);

		if (list_empty(&wait.list))
			list_add_tail(&wait.list, &tags->wait);

		spin_unlock_irq(&tags->lock);
		io_schedule();
	} while (1);

	if (!list_empty(&wait.list))
		list_del(&wait.list);

	spin_unlock_irq(&tags->lock);
	return tag;
}

unsigned int blk_mq_get_tag(struct blk_mq_tags *tags, gfp_t gfp, bool reserved)
{
	if (!reserved)
		return __blk_mq_get_tag(tags, gfp);

	return __blk_mq_get_reserved_tag(tags, gfp);
}

static void __blk_mq_put_tag(struct blk_mq_tags *tags, unsigned int tag)
{
	struct blk_mq_tag_map *map;
	unsigned long flags;

	BUG_ON(tag >= tags->nr_tags);

	local_irq_save(flags);
	map = this_cpu_ptr(tags->free_maps);

	map->freelist[map->nr_free] = tag;
	map->nr_free++;

	if (map->nr_free >= tags->max_cache ||
	    !list_empty_careful(&tags->wait)) {
		spin_lock(&tags->lock);
		__blk_mq_tag_return(tags, map, tags->batch_move);
		spin_unlock(&tags->lock);
	}

	local_irq_restore(flags);
}

static void __blk_mq_put_reserved_tag(struct blk_mq_tags *tags,
				      unsigned int tag)
{
	unsigned long flags;

	spin_lock_irqsave(&tags->lock, flags);
	tags->reservelist[tags->nr_reserved] = tag;
	tags->nr_reserved++;

	if (!list_empty(&tags->wait))
		__wake_waiters(tags, 1);

	spin_unlock_irqrestore(&tags->lock, flags);
}

void blk_mq_put_tag(struct blk_mq_tags *tags, unsigned int tag)
{
	if (tag >= tags->reserved_tags)
		__blk_mq_put_tag(tags, tag);
	else
		__blk_mq_put_reserved_tag(tags, tag);
}

void blk_mq_tag_busy_iter(struct blk_mq_tags *tags,
			  void (*fn)(void *, unsigned long *), void *data)
{
	unsigned long flags, *tag_map;
	unsigned int i, j;
	size_t map_size;

	map_size = ALIGN(tags->nr_tags, BITS_PER_LONG) / BITS_PER_LONG;
	tag_map = kzalloc(map_size * sizeof(unsigned long), GFP_ATOMIC);
	if (!tag_map)
		return;

	local_irq_save(flags);

	for_each_online_cpu(i) {
		struct blk_mq_tag_map *map = per_cpu_ptr(tags->free_maps, i);

		for (j = 0; j < map->nr_free; j++)
			__set_bit(map->freelist[j], tag_map);
	}

	if (tags->nr_free || tags->nr_reserved) {
		spin_lock(&tags->lock);

		if (tags->nr_reserved)
			for (j = 0; j < tags->nr_reserved; j++)
				__set_bit(tags->reservelist[j], tag_map);

		if (tags->nr_free)
			for (j = 0; j < tags->nr_free; j++)
				__set_bit(tags->freelist[j], tag_map);

		spin_unlock(&tags->lock);
	}

	local_irq_restore(flags);

	fn(data, tag_map);
	kfree(tag_map);
}

static void blk_mq_tag_notify(void *data, unsigned long action,
			      unsigned int cpu)
{
	/*
	 * Move entries from this CPU to global pool
	 */
	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		struct blk_mq_tags *tags = data;
		struct blk_mq_tag_map *map = per_cpu_ptr(tags->free_maps, cpu);

		if (map->nr_free)
			blk_mq_tag_return(tags, map, map->nr_free);
	}
}

struct blk_mq_tags *blk_mq_init_tags(unsigned int nr_tags,
				     unsigned int reserved_tags, int node)
{
	struct blk_mq_tags *tags;
	size_t map_size;

	if (nr_tags > BLK_MQ_TAG_MAX) {
		pr_err("blk-mq: tag depth too large\n");
		return NULL;
	}

	tags = kzalloc_node(sizeof(*tags), GFP_KERNEL, node);
	if (!tags)
		return NULL;

	map_size = sizeof(struct blk_mq_tag_map) + nr_tags * sizeof(int);
	tags->free_maps = __alloc_percpu(map_size, sizeof(void *));
	if (!tags->free_maps)
		goto err_free_maps;

	tags->freelist = kmalloc_node(sizeof(int) * nr_tags, GFP_KERNEL, node);
	if (!tags->freelist)
		goto err_freelist;

	if (reserved_tags) {
		tags->reservelist = kmalloc_node(sizeof(int) * reserved_tags,
							GFP_KERNEL, node);
		if (!tags->reservelist)
			goto err_reservelist;
	}

	spin_lock_init(&tags->lock);
	INIT_LIST_HEAD(&tags->wait);
	tags->nr_tags = nr_tags;
	tags->reserved_tags = reserved_tags;
	tags->max_cache = nr_tags / num_possible_cpus();
	if (tags->max_cache < 4)
		tags->max_cache = 4;
	else if (tags->max_cache > 64)
		tags->max_cache = 64;

	tags->batch_move = tags->max_cache / 2;

	/*
	 * Reserved tags are first
	 */
	if (reserved_tags) {
		tags->nr_reserved = 0;
		while (reserved_tags--) {
			tags->reservelist[tags->nr_reserved] =
							tags->nr_reserved;
			tags->nr_reserved++;
		}
	}

	/*
	 * Rest of the tags start at the queue list
	 */
	tags->nr_free = 0;
	while (nr_tags - tags->nr_reserved) {
		tags->freelist[tags->nr_free] = tags->nr_free +
							tags->nr_reserved;
		nr_tags--;
		tags->nr_free++;
	}

	blk_mq_init_cpu_notifier(&tags->cpu_notifier, blk_mq_tag_notify, tags);
	blk_mq_register_cpu_notifier(&tags->cpu_notifier);
	return tags;

err_reservelist:
	kfree(tags->freelist);
err_freelist:
	free_percpu(tags->free_maps);
err_free_maps:
	kfree(tags);
	return NULL;
}

void blk_mq_free_tags(struct blk_mq_tags *tags)
{
	blk_mq_unregister_cpu_notifier(&tags->cpu_notifier);
	free_percpu(tags->free_maps);
	kfree(tags->freelist);
	kfree(tags->reservelist);
	kfree(tags);
}

ssize_t blk_mq_tag_sysfs_show(struct blk_mq_tags *tags, char *page)
{
	char *orig_page = page;
	unsigned long flags;
	struct list_head *tmp;
	int waiters;
	int cpu;

	if (!tags)
		return 0;

	spin_lock_irqsave(&tags->lock, flags);

	page += sprintf(page, "nr_tags=%u, reserved_tags=%u, batch_move=%u,"
			" max_cache=%u\n", tags->nr_tags, tags->reserved_tags,
			tags->batch_move, tags->max_cache);

	waiters = 0;
	list_for_each(tmp, &tags->wait)
		waiters++;

	page += sprintf(page, "nr_free=%u, nr_reserved=%u, waiters=%u\n",
			tags->nr_free, tags->nr_reserved, waiters);

	for_each_online_cpu(cpu) {
		struct blk_mq_tag_map *map = per_cpu_ptr(tags->free_maps, cpu);

		page += sprintf(page, "  cpu%02u: nr_free=%u\n", cpu,
					map->nr_free);
	}

	spin_unlock_irqrestore(&tags->lock, flags);
	return page - orig_page;
}
