/*
 * Don't allow the cache to grow beyond this size.
 */
#define IO_ALLOC_CACHE_MAX	512

static inline bool io_alloc_cache_store(struct io_alloc_cache *cache)
{
	if (cache->nr_cached < IO_ALLOC_CACHE_MAX) {
		cache->nr_cached++;
		return true;
	}
	return false;
}

static inline void io_alloc_cache_init(struct io_alloc_cache *cache)
{
	INIT_HLIST_HEAD(&cache->list);
	cache->nr_cached = 0;
}
