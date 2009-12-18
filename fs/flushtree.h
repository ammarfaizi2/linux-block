#ifndef WB_FLUSHTREE_H
#define WB_FLUSHTREE_H

void flush_tree_insert(struct inode *inode);
void flush_tree_remove(struct inode *inode);
struct inode *flush_tree_next(struct bdi_writeback *wb, unsigned long start,
				unsigned long prev);

#endif
