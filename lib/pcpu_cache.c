#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/pcpu_cache.h>

void pcpu_cache_free(struct pcpu_alloc_cache *cache, void *ptr)
{
	struct pcpu_cache *pc;
	unsigned long flags;

	local_irq_save(flags);

	pc = this_cpu_ptr(cache->pcpu);
	if (pc->cache_count == PCPU_CACHE_SIZE) {
		kmem_cache_free_bulk(cache->slab, pc->cache_count,
					pc->cache_entries);
		pc->cache_count = 0;
	}

	pc->cache_entries[pc->cache_count++] = ptr;
	local_irq_restore(flags);
}

static void *__pcpu_cache_alloc(struct pcpu_alloc_cache *cache)
{
	struct pcpu_cache *pc;
	void *ret = NULL;

	pc = raw_cpu_ptr(cache->pcpu);
	if (pc->cache_count) {
		local_irq_disable();
		pc = this_cpu_ptr(cache->pcpu);
		if (pc->cache_count)
			ret = pc->cache_entries[--pc->cache_count];
		local_irq_enable();
	}

	return ret;
}

void *pcpu_cache_alloc(struct pcpu_alloc_cache *cache, gfp_t gfp_mask)
{
	void *ret;

	ret = __pcpu_cache_alloc(cache);
	if (ret)
		return ret;

	return kmem_cache_alloc(cache->slab, gfp_mask);
}

void pcpu_cache_init(struct pcpu_alloc_cache *cache, struct pcpu_cache *pc,
		     struct kmem_cache *slab)
{
	cache->pcpu = pc;
	cache->slab = slab;
}

void pcpu_cache_exit(struct pcpu_alloc_cache *cache)
{
	int i;

	for_each_possible_cpu(i) {
		struct pcpu_cache *pc = per_cpu_ptr(cache->pcpu, i);

		if (!pc->cache_count)
			continue;

		kmem_cache_free_bulk(cache->slab, pc->cache_count,
					pc->cache_entries);
		pc->cache_count = 0;
	}
}
