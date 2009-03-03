#ifndef __EXTENTMAP__
#define __EXTENTMAP__

#include <linux/rbtree.h>

/* special values for struct extent_map->block_start */
#define EXTENT_MAP_LAST_BYTE (u64)-4
#define EXTENT_MAP_HOLE (u64)-3
#define EXTENT_MAP_INLINE (u64)-2
#define EXTENT_MAP_DELALLOC (u64)-1

/* bit flags for struct extent_map->flags */
#define EXTENT_MAP_COMMIT_REQUIRED 1
#define EXTENT_MAP_HOLE_FILLED 2

struct extent_map_tree {
	struct rb_root map;
	spinlock_t lock;
	struct extent_map *last;
};

struct extent_map {
	struct rb_node rb_node;
	loff_t start;
	u64 len;
	sector_t block_start;
	struct block_device *bdev;
	atomic_t refs;
	unsigned long flags;
};

static inline loff_t extent_map_end(struct extent_map *em)
{
	return em->start + em->len;
}

static inline loff_t extent_map_block_end(struct extent_map *em)
{
	return em->block_start + em->len;
}

void extent_map_tree_init(struct extent_map_tree *tree);
struct extent_map *lookup_extent_mapping(struct extent_map_tree *tree,
					 loff_t start, u64 len);
struct extent_map *map_extent_get_block(struct extent_map_tree *tree,
					struct address_space *mapping,
					loff_t start, u64 len, int create,
					gfp_t gfp_mask, get_block_t get_block);
int add_extent_mapping(struct extent_map_tree *tree,
		       struct extent_map *em);
int remove_extent_mappings(struct extent_map_tree *tree,
			   loff_t start, u64 len);
int remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em);
struct extent_map *alloc_extent_map(gfp_t mask);
void free_extent_map(struct extent_map *em);
int __init extent_map_init(void);
void __exit extent_map_exit(void);
#endif
