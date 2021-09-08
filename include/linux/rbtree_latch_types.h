/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Latched RB-trees
 *
 * Copyright (C) 2015 Intel Corp., Peter Zijlstra <peterz@infradead.org>
 *
 * Since RB-trees have non-atomic modifications they're not immediately suited
 * for RCU/lockless queries. Even though we made RB-tree lookups non-fatal for
 * lockless lookups; we cannot guarantee they return a correct result.
 *
 * The simplest solution is a seqlock + RB-tree, this will allow lockless
 * lookups; but has the constraint (inherent to the seqlock) that read sides
 * cannot nest in write sides.
 *
 * If we need to allow unconditional lookups (say as required for NMI context
 * usage) we need a more complex setup; this data structure provides this by
 * employing the latch technique -- see @raw_write_seqcount_latch -- to
 * implement a latched RB-tree which does allow for unconditional lookups by
 * virtue of always having (at least) one stable copy of the tree.
 *
 * However, while we have the guarantee that there is at all times one stable
 * copy, this does not guarantee an iteration will not observe modifications.
 * What might have been a stable copy at the start of the iteration, need not
 * remain so for the duration of the iteration.
 *
 * Therefore, this does require a lockless RB-tree iteration to be non-fatal;
 * see the comment in lib/rbtree.c. Note however that we only require the first
 * condition -- not seeing partial stores -- because the latch thing isolates
 * us from loops. If we were to interrupt a modification the lookup would be
 * pointed at the stable tree and complete while the modification was halted.
 */

#ifndef RB_TREE_LATCH_TYPES_H
#define RB_TREE_LATCH_TYPES_H

#include <linux/rbtree.h>

struct latch_tree_node {
	struct rb_node node[2];
};

#endif /* RB_TREE_LATCH_TYPES_H */
