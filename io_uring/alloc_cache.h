static inline void io_alloc_cache_init(struct io_alloc_cache *cache)
{
	INIT_HLIST_HEAD(&cache->list);
}
