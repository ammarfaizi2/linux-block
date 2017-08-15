#ifndef PCPU_CACHE_H
#define PCPU_CACHE_H

#define PCPU_CACHE_SIZE	16

struct pcpu_cache {
	unsigned int cache_count;
	void *cache_entries[PCPU_CACHE_SIZE];
};

struct pcpu_alloc_cache {
	struct pcpu_cache __percpu *pcpu;
	struct kmem_cache *slab;
};

void *pcpu_cache_alloc(struct pcpu_alloc_cache *, gfp_t);
void pcpu_cache_free(struct pcpu_alloc_cache *, void *);
void pcpu_cache_init(struct pcpu_alloc_cache *, struct pcpu_cache *,
			struct kmem_cache *);
void pcpu_cache_exit(struct pcpu_alloc_cache *);

#endif
