#include <linux/fs.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/rbtree.h>

#include "flushtree.h"

#define rb_to_inode(node) rb_entry((node), struct inode, i_flush_node)

/*
 * When inodes are parked for writeback they are parked in the
 * flush_tree. The flush tree is a data structure based on an rb tree.
 *
 * Duplicate keys are handled by making a list in the tree for each key
 * value. The order of how we choose the next inode to flush is decided
 * by two fields. First the earliest dirtied_when value. If there are
 * duplicate dirtied_when values then the earliest i_flushed_when value
 * determines who gets flushed next.
 *
 * The flush tree organizes the dirtied_when keys with the rb_tree. Any
 * inodes with a duplicate dirtied_when value are link listed together. This
 * link list is sorted by the inode's i_flushed_when. When both the
 * dirtied_when and the i_flushed_when are indentical the order in the
 * linked list determines the order we flush the inodes.
 */

/*
 * Find a rb_node matching the key in the flush tree. There are no duplicate
 * rb_nodes in the tree. Instead they are chained off the first node.
 */
static struct inode *flush_tree_search(struct bdi_writeback *wb,
				       unsigned long ts)
{
	struct rb_node *n = wb->flush_tree.rb_node;

	while (n) {
		struct inode *inode = rb_to_inode(n);

		if (time_before(ts, inode->dirtied_when))
			n = n->rb_left;
		else if (time_after(ts, inode->dirtied_when))
			n = n->rb_right;
		else
			return inode;
	}

	return NULL;
}

/*
 * Inserting an inode into the flush tree. The tree is keyed by the
 * dirtied_when member.
 *
 * If there is a duplicate key in the tree already the new inode is put
 * on the tail of a list of the rb_node.
 * All inserted inodes must have one of the I_DIRTY flags set.
 */
void flush_tree_insert(struct inode *inode)
{
	struct bdi_writeback *wb = &inode_to_bdi(inode)->wb;
	struct rb_node **new = &wb->flush_tree.rb_node;
	struct rb_node *parent = NULL;

	BUG_ON((inode->i_state & I_DIRTY) == 0);
	BUG_ON(inode->i_state & (I_FREEING|I_CLEAR));
	BUG_ON(!RB_EMPTY_NODE(&inode->i_flush_node));

	list_del_init(&inode->i_list);
	while (*new) {
		struct inode *this = rb_to_inode(*new);

		parent = *new;
		if (time_before(inode->dirtied_when, this->dirtied_when))
			new = &parent->rb_left;
		else if (time_after(inode->dirtied_when, this->dirtied_when))
			new = &parent->rb_right;
		else {
			list_add_tail(&inode->i_list, &this->i_list);
			return;
		}
	}

	/* Add in the new node and rebalance the tree */
	rb_link_node(&inode->i_flush_node, parent, new);
	rb_insert_color(&inode->i_flush_node, &wb->flush_tree);
}

/*
 * Here we return the inode that has the smallest key in the flush tree
 * that is greater than the parameter "prev_time".
 */
static struct inode *flush_tree_min_greater(struct bdi_writeback *wb,
					    unsigned long prev_time)
{
	struct rb_node *node = wb->flush_tree.rb_node;
	struct inode *best = NULL;

	while (node) {
		struct inode *data = rb_to_inode(node);

		/* Just trying to get lucky */
		if ((prev_time + 1) == data->dirtied_when)
			return data;

		/* If this value is greater than our prev_time and is
		less than the best so far, this is our new best so far.*/
		if ((data->dirtied_when > prev_time) &&
		    (!best || best->dirtied_when > data->dirtied_when))
			best = data;

		/* Search all the way down to the bottom of the tree */
		if (time_before(prev_time, data->dirtied_when))
			node = node->rb_left;
		else if (time_after_eq(prev_time, data->dirtied_when))
			node = node->rb_right;
	}

	return best;
}

/*
 * Here is where we interate to find the next inode to process. The
 * strategy is to first look for any other inodes with the same dirtied_when
 * value. If we have already processed that node then we need to find
 * the next highest dirtied_when value in the tree.
 */
struct inode *flush_tree_next(struct bdi_writeback *wb,
			      unsigned long start_time,
			      unsigned long prev_time)
{
	struct inode *inode = flush_tree_search(wb, prev_time);

	/* We have a duplicate timed inode as the last processed */
	if (inode && time_before(inode->i_flushed_when, start_time))
		return inode;

	/* Now we have to find the oldest one next */
	return flush_tree_min_greater(wb, prev_time);
}

/* Removing a node from the flushtree. */
void flush_tree_remove(struct inode *inode)
{
	struct bdi_writeback *wb = &inode_to_bdi(inode)->wb;
	struct rb_node *rb_node = &inode->i_flush_node;
	struct rb_root *rb_root = &wb->flush_tree;

	BUG_ON((inode->i_state & I_DIRTY) == 0);

	/* There is no chain on this inode. Just remove it from the tree */
	if (list_empty(&inode->i_list)) {
		BUG_ON(RB_EMPTY_NODE(rb_node));
		rb_erase(rb_node, rb_root);
		RB_CLEAR_NODE(rb_node);
		return;
	}

	/* This node is on a chain AND is in the rb_tree */
	if (!RB_EMPTY_NODE(rb_node)) {
		struct inode *new = list_entry(inode->i_list.next,
					       struct inode, i_list);

		rb_replace_node(rb_node, &new->i_flush_node, rb_root);
		RB_CLEAR_NODE(rb_node);
	}
	/* Take it off the list */
	list_del_init(&inode->i_list);
}
