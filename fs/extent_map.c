#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/extent_map.h>

static struct kmem_cache *extent_map_cache;

int __init extent_map_init(void)
{
	extent_map_cache = KMEM_CACHE(extent_map, SLAB_MEM_SPREAD);
	if (!extent_map_cache)
		return -ENOMEM;
	return 0;
}

void __exit extent_map_exit(void)
{
	if (extent_map_cache)
		kmem_cache_destroy(extent_map_cache);
}

void extent_map_tree_init(struct extent_map_tree *tree)
{
	tree->map.rb_node = NULL;
	tree->last = NULL;
	spin_lock_init(&tree->lock);
}
EXPORT_SYMBOL(extent_map_tree_init);

struct extent_map *alloc_extent_map(gfp_t mask)
{
	struct extent_map *em;
	em = kmem_cache_alloc(extent_map_cache, mask);
	if (!em || IS_ERR(em))
		return em;
	atomic_set(&em->refs, 1);
	em->flags = 0;
	return em;
}
EXPORT_SYMBOL(alloc_extent_map);

void free_extent_map(struct extent_map *em)
{
	if (!em)
		return;
	if (atomic_dec_and_test(&em->refs))
		kmem_cache_free(extent_map_cache, em);
}
EXPORT_SYMBOL(free_extent_map);

static struct rb_node *tree_insert(struct rb_root *root, u64 offset,
				   struct rb_node *node)
{
	struct rb_node ** p = &root->rb_node;
	struct rb_node * parent = NULL;
	struct extent_map *entry;

	while(*p) {
		parent = *p;
		entry = rb_entry(parent, struct extent_map, rb_node);

		if (offset < entry->start)
			p = &(*p)->rb_left;
		else if (offset >= entry->start + entry->len)
			p = &(*p)->rb_right;
		else
			return parent;
	}

	entry = rb_entry(node, struct extent_map, rb_node);
	rb_link_node(node, parent, p);
	rb_insert_color(node, root);
	return NULL;
}

static struct rb_node *__tree_search(struct rb_root *root, u64 offset,
				   struct rb_node **prev_ret)
{
	struct rb_node * n = root->rb_node;
	struct rb_node *prev = NULL;
	struct extent_map *entry;
	struct extent_map *prev_entry = NULL;

	while(n) {
		entry = rb_entry(n, struct extent_map, rb_node);
		prev = n;
		prev_entry = entry;

		if (offset < entry->start)
			n = n->rb_left;
		else if (offset >= entry->start + entry->len)
			n = n->rb_right;
		else
			return n;
	}
	if (!prev_ret)
		return NULL;
	while(prev && (offset >= prev_entry->start + prev_entry->len)) {
		prev = rb_next(prev);
		prev_entry = rb_entry(prev, struct extent_map, rb_node);
	}
	*prev_ret = prev;
	return NULL;
}

static inline struct rb_node *tree_search(struct rb_root *root, u64 offset)
{
	struct rb_node *prev;
	struct rb_node *ret;
	ret = __tree_search(root, offset, &prev);
	if (!ret)
		return prev;
	return ret;
}

static int tree_delete(struct rb_root *root, u64 offset)
{
	struct rb_node *node;
	struct extent_map *entry;

	node = __tree_search(root, offset, NULL);
	if (!node)
		return -ENOENT;
	entry = rb_entry(node, struct extent_map, rb_node);
	rb_erase(node, root);
	return 0;
}

static int mergable_maps(struct extent_map *prev, struct extent_map *next)
{
	if (extent_map_end(prev) == next->start &&
	    prev->flags == next->flags &&
	    ((next->block_start == EXTENT_MAP_HOLE &&
	      prev->block_start == EXTENT_MAP_HOLE) ||
	     (next->block_start == EXTENT_MAP_INLINE &&
	      prev->block_start == EXTENT_MAP_INLINE) ||
	     (next->block_start == EXTENT_MAP_DELALLOC &&
	      prev->block_start == EXTENT_MAP_DELALLOC) ||
	     (next->block_start < EXTENT_MAP_LAST_BYTE - 1 &&
	      next->block_start == extent_map_block_end(prev)))) {
		return 1;
	}
	return 0;
}

/*
 * add_extent_mapping tries a simple forward/backward merge with existing
 * mappings.  The extent_map struct passed in will be inserted into
 * the tree directly (no copies made, just a reference taken).
 */
int add_extent_mapping(struct extent_map_tree *tree,
		       struct extent_map *em)
{
	int ret = 0;
	struct extent_map *merge = NULL;
	struct rb_node *rb;
	unsigned long flags;

	spin_lock_irqsave(&tree->lock, flags);
	rb = tree_insert(&tree->map, em->start, &em->rb_node);
	if (rb) {
		ret = -EEXIST;
		goto out;
	}
	atomic_inc(&em->refs);
	if (em->start != 0) {
		rb = rb_prev(&em->rb_node);
		if (rb)
			merge = rb_entry(rb, struct extent_map, rb_node);
		if (rb && mergable_maps(merge, em)) {
			em->start = merge->start;
			em->len += merge->len;
			em->block_start = merge->block_start;
			rb_erase(&merge->rb_node, &tree->map);
			free_extent_map(merge);
		}
	 }
	rb = rb_next(&em->rb_node);
	if (rb)
		merge = rb_entry(rb, struct extent_map, rb_node);
	if (rb && mergable_maps(em, merge)) {
		em->len += merge->len;
		rb_erase(&merge->rb_node, &tree->map);
		free_extent_map(merge);
	}
	tree->last = em;
out:
	spin_unlock_irqrestore(&tree->lock, flags);
	return ret;
}
EXPORT_SYMBOL(add_extent_mapping);

/*
 * lookup_extent_mapping returns the first extent_map struct in the
 * tree that intersects the [start, len] range.  There may
 * be additional objects in the tree that intersect, so check the object
 * returned carefully to make sure you don't need additional lookups.
 */
struct extent_map *lookup_extent_mapping(struct extent_map_tree *tree,
					 u64 start, u64 len)
{
	struct extent_map *em;
	struct extent_map *last;
	struct rb_node *rb_node;
	unsigned long flags;

	spin_lock_irqsave(&tree->lock, flags);
	last = tree->last;
	if (last && start >= last->start &&
	    start + len <= extent_map_end(last)) {
		em = last;
		atomic_inc(&em->refs);
		goto out;
	}
	rb_node = tree_search(&tree->map, start);
	if (!rb_node) {
		em = NULL;
		goto out;
	}
	if (IS_ERR(rb_node)) {
		em = ERR_PTR(PTR_ERR(rb_node));
		goto out;
	}
	em = rb_entry(rb_node, struct extent_map, rb_node);
	if (extent_map_end(em) <= start || em->start >= start + len) {
		em = NULL;
		goto out;
	}
	atomic_inc(&em->refs);
	tree->last = em;
out:
	spin_unlock_irqrestore(&tree->lock, flags);
	return em;
}
EXPORT_SYMBOL(lookup_extent_mapping);

/*
 * removes an extent_map struct from the tree.  No reference counts are
 * dropped, and no checks are done to  see if the range is in use
 */
int remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&tree->lock, flags);
	ret = tree_delete(&tree->map, em->start);
	tree->last = NULL;
	spin_unlock_irqrestore(&tree->lock, flags);
	return ret;
}
EXPORT_SYMBOL(remove_extent_mapping);

static struct extent_map *__map_extent(struct extent_map_tree *tree,
				       struct address_space *mapping,
				       u64 start, u64 len, int create,
				       gfp_t gfp_mask, get_block_t get_block)
{
	struct inode *inode = mapping->host;
	struct extent_map *em;
	struct buffer_head result;
	sector_t start_block;
	u64 cur_len;
	int ret;

again:
	em = lookup_extent_mapping(tree, start, len);
	if (em) {
		/*
		 * we may have found an extent that starts after the
		 * requested range.  Double check and alter the length
		 * appropriately
		 */
		if (em->start > start) {
			len = em->start - start;
		} else if (!create || em->block_start != EXTENT_MAP_HOLE) {
			return em;
		}
		free_extent_map(em);

	}
	if (gfp_mask & GFP_ATOMIC)
		return NULL;

	em = alloc_extent_map(GFP_NOFS);
	if (!em)
		return ERR_PTR(-ENOMEM);

	len = min_t(u64, len, (size_t)-1);
	result.b_state = 0;
	result.b_size = len;
	start_block = start >> inode->i_blkbits;

	if (len < inode->i_sb->s_blocksize) {
		printk("warning2: mapping length %Lu\n", len);
	}

	/*
	 * FIXME if there are errors later on, we end up exposing stale
	 * data on disk while filling holes.
	 */
	ret = get_block(inode, start_block,
			&result, create);
	if (ret < 0) {
		free_extent_map(em);
		return ERR_PTR(ret);
	}

	cur_len = result.b_size;
	em->start = start;
	em->len = cur_len;
	em->bdev = result.b_bdev;

	if (create && buffer_new(&result)) {
		remove_extent_mappings(tree, em->start, em->len);
		em->flags = (1 << EXTENT_MAP_HOLE_FILLED);
	}

	if (buffer_mapped(&result))
		em->block_start = (u64)result.b_blocknr << inode->i_blkbits;
	else {
		em->block_start = EXTENT_MAP_HOLE;
		if (create) {
			free_extent_map(em);
			return ERR_PTR(-EIO);
		}
	}
	ret = add_extent_mapping(tree, em);
	if (ret == -EEXIST) {
		free_extent_map(em);
		goto again;
	}
	return em;
}

struct extent_map *map_extent_get_block(struct extent_map_tree *tree,
					struct address_space *mapping,
					u64 start, u64 len, int create,
					gfp_t gfp_mask, get_block_t get_block)
{
	struct extent_map *em;
	u64 last;
	u64 map_ahead_len = 0;

	em = __map_extent(tree, mapping, start, len, create,
			  gfp_mask, get_block);

	/*
	 * if we're doing a write or we found a large extent, return it
	 */
	if (IS_ERR(em) || !em || create || start + len < extent_map_end(em)) {
		return em;
	}

	/*
	 * otherwise, try to walk forward a bit and see if we can build
	 * something bigger.
	 */
	do {
		last = extent_map_end(em);
		free_extent_map(em);
		em = __map_extent(tree, mapping, last, len, create,
				  gfp_mask, get_block);
		if (IS_ERR(em) || !em)
			break;
		map_ahead_len += extent_map_end(em) - last;
	} while(em->start <= start && start + len <= extent_map_end(em) &&
		em->block_start < EXTENT_MAP_LAST_BYTE &&
		map_ahead_len < (512 * 1024));

	/* make sure we return the extent for this range */
	if (!em || IS_ERR(em) || em->start > start ||
	    start + len > extent_map_end(em)) {
		free_extent_map(em);
		em = __map_extent(tree, mapping, start, len, create,
				  gfp_mask, get_block);
	}
	return em;
}
EXPORT_SYMBOL(map_extent_get_block);

int remove_extent_mappings(struct extent_map_tree *tree,
			   u64 start, u64 len)
{
	struct extent_map *em;

	while((em = lookup_extent_mapping(tree, start, len))) {
		remove_extent_mapping(tree, em);
		/* once for us */
		free_extent_map(em);
		/* once for the tree */
		free_extent_map(em);
	}
	return 0;
}
EXPORT_SYMBOL(remove_extent_mappings);
