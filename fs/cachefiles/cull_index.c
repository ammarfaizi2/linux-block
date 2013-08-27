/* Culling Index management
 *
 * Copyright (C) 2009 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define __KDEBUG
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/nfs4.h>
#include <linux/exportfs.h>
#include <linux/splice.h>
#include "internal.h"

#define BITS_PER_PAGE (PAGE_SIZE * 8)
#define BITS_PER_BITMAP BITS_PER_PAGE
#define SLOTS_PER_BITMAP BITS_PER_PAGE
#define BITS_PER_PAGE_MASK (BITS_PER_BITMAP - 1)
#define slot_to_map_number(INDEX) ((INDEX) >> (PAGE_SHIFT + 3))

/*
 * release the storage for an index bitmap
 */
void cachefiles_cx_free_bitmap(struct cachefiles_cache *cache)
{
	struct cachefiles_cx_bitmap *bm;

	_enter("");

	while (!RB_EMPTY_ROOT(&cache->cull_bitmap)) {
		bm = rb_entry(cache->cull_bitmap.rb_node,
			      struct cachefiles_cx_bitmap, rb);
		rb_erase(&bm->rb, &cache->cull_bitmap);
		put_page(bm->free_slots);
		put_page(bm->cullable_slots);
		kfree(bm);
	}

	_leave("");
}

/*
 * determine the size of the entries in the index
 */
static int cachefiles_cx_check_size(struct cachefiles_cache *cache)
{
	void *scratch;
	int ret, dir_len, file_len, ixlen;

	_enter("");

	ret = -ENOMEM;
	scratch = kmalloc(MAX_HANDLE_SZ, GFP_KERNEL);
	if (!scratch)
		goto error;

	/* determine how big a directory FH might be */
	/* Note, exportfs_encode_fh works in terms of 4 byte sequences, not bytes. */
	dir_len = MAX_HANDLE_SZ / sizeof(u32);
	ret = exportfs_encode_fh(cache->graveyard, scratch, &dir_len, 1);
	if (ret < 0) {
		pr_err("Unable to determine Backing FS dir FH size: error=%d",
		       ret);
		goto error_free;
	}

	_debug("- dir FH %d", dir_len);

	/* determine how big a file FH might be */
	file_len = MAX_HANDLE_SZ / sizeof(u32);
	ret = exportfs_encode_fh(cache->cull_index->f_path.dentry, scratch,
				 &file_len, 1);
	if (ret < 0) {
		pr_err("Unable to determine Backing FS file FH size: error=%d",
		       ret);
		goto error_free;
	}

	_debug("- file FH %d", file_len);

	kfree(scratch);

	/* the index entry size is the largest of the two FH sizes plus a byte
	 * for type and a byte for length */
	ixlen = max(dir_len, file_len) * sizeof(u32) + 2;
	cache->cx_entsize = ixlen;
	cache->cx_nperpage = PAGE_SIZE / ixlen;

	_debug("- ent=%hu e/p=%hu", cache->cx_entsize, cache->cx_nperpage);

	return cachefiles_check_cull_index(cache);

error_free:
	kfree(scratch);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * allocate enough bitmap blocks to cover the current size of the index file
 */
static int cachefiles_cx_alloc_bitmap(struct cachefiles_cache *cache)
{
	struct cachefiles_cx_bitmap *bm;
	struct rb_node *last, **insert;
	unsigned long fsize, loop, nbitmaps, nslots;
	unsigned long naslots;

	_enter("");

	fsize = i_size_read(file_inode(cache->cull_index));
	nslots = (fsize + PAGE_SIZE - 1) >> PAGE_SHIFT;
	nslots *= cache->cx_nperpage;
	cache->cull_nslots = nslots;

	nbitmaps = nslots + SLOTS_PER_BITMAP - 1;
	nbitmaps >>= ilog2(SLOTS_PER_BITMAP);

	_debug("nslots=%lu nbitmaps=%lu", nslots, nbitmaps);

	naslots = (i_size_read(file_inode(cache->cull_atimes)) >> 2);
	if (nslots != naslots) {
		pr_err("Warning: index slots (%lu) does not match atime slots (%lu)\n",
		       nslots, naslots);
		cachefiles_mark_dirty(cache);
	}

	insert = &cache->cull_bitmap.rb_node;
	last = NULL;
	for (loop = 0; loop < nbitmaps; loop++) {
		bm = kmalloc(sizeof(*bm), GFP_KERNEL);
		if (!bm)
			goto error;
		bm->free_slots = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!bm->free_slots)
			goto error_no_page;
		bm->cullable_slots = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!bm->cullable_slots)
			goto error_no_page_2;
		bm->offset = loop;
		/* assume bitmap is full until we scan it for free slots. */
		bm->nfreeslots = 0;
		bm->nslots = min(nslots, SLOTS_PER_BITMAP);
		nslots -= bm->nslots;

		/* barring the first, we only ever add a node at offset + 1 of
		 * the last node we added */
		rb_link_node(&bm->rb, last, insert);
		rb_insert_color(&bm->rb, &cache->cull_bitmap);
		last = &bm->rb;
		insert = &bm->rb.rb_right;
	}

	_leave(" = 0");
	return 0;

error_no_page_2:
	put_page(bm->free_slots);
error_no_page:
	kfree(bm);
error:
	cachefiles_cx_free_bitmap(cache);
	_leave(" = -ENOMEM");
	return -ENOMEM;
}

static struct cachefiles_cx_bitmap *
__cachefiles_cx_find_bitmap(struct rb_node *root,
			    unsigned index,
			    struct cachefiles_cx_bitmap *bm)
{
	struct rb_node *p;
	unsigned offset;

	_enter(",%u,", index);

	offset = slot_to_map_number(index);
	if (!bm || bm->offset != offset) {
		p = root;
		while (p) {
			bm = rb_entry(p, struct cachefiles_cx_bitmap, rb);

			if (offset < bm->offset)
				p = p->rb_left;
			else if (offset > bm->offset)
				p = p->rb_right;
			else if (offset == bm->offset)
				return bm;
			else
				return NULL;
		}
	}

	return bm;
}

/*
 * mark an empty slot in the bitmap
 * - the caller is responsible for locking cull_bitmap_lock if necessary
 */
static int cachefiles_cx_mark_empty(struct cachefiles_cache *cache,
				    unsigned index,
				    struct cachefiles_cx_bitmap **_last_bm)
{
	struct cachefiles_cx_bitmap *bm;
	unsigned long *bitmap;

	_enter(",%u,", index);

	*_last_bm = bm = __cachefiles_cx_find_bitmap(cache->cull_bitmap.rb_node,
						     index,
						     *_last_bm);
	if (!bm) {
		_leave(" = -EIO");
		return -EIO;
	}
	bm->nfreeslots++;

	bitmap = kmap_atomic(bm->free_slots);
	__set_bit(index & BITS_PER_PAGE_MASK, bitmap);
	kunmap_atomic(bitmap);

	bitmap = kmap_atomic(bm->cullable_slots);
	__clear_bit(index & BITS_PER_PAGE_MASK, bitmap);
	kunmap_atomic(bitmap);
	return 0;
}

/*
 * mark an in-use slot in the cullable bitmap
 * - the caller is responsible for locking cull_bitmap_lock if necessary
 */
static int __cachefiles_cx_mark_cullable(struct cachefiles_cache *cache,
					 unsigned index, bool cullable,
					 struct cachefiles_cx_bitmap **_last_bm)
{
	struct cachefiles_cx_bitmap *bm;
	unsigned long *bitmap;

	_enter(",%u,%u,", index, cullable);

	*_last_bm = bm = __cachefiles_cx_find_bitmap(cache->cull_bitmap.rb_node,
						     index,
						     *_last_bm);
	if (!bm) {
		_leave(" = -EIO");
		return -EIO;
	}

	bitmap = kmap_atomic(bm->cullable_slots);
	if (cullable)
		__set_bit(index & BITS_PER_PAGE_MASK, bitmap);
	else
		__clear_bit(index & BITS_PER_PAGE_MASK, bitmap);
	kunmap_atomic(bitmap);
	return 0;
}

/*
 * mark an in-use slot in the cullable bitmap
 * - the caller is responsible for locking cull_bitmap_lock if necessary
 */
void cachefiles_cx_mark_cullable(struct cachefiles_cache *cache,
				 unsigned slot, bool cullable)
{
	struct cachefiles_cx_bitmap *last_bm = NULL;

	if (slot != CACHEFILES_NO_CULL_SLOT &&
	    slot != CACHEFILES_PINNED) {
		spin_lock(&cache->cull_bitmap_lock);
		__cachefiles_cx_mark_cullable(cache, slot, cullable, &last_bm);
		spin_unlock(&cache->cull_bitmap_lock);
	}
}

/*
 * actor for page-by-page scanning of the cull index file
 */
static int cachefiles_cx_generate_actor(struct pipe_inode_info *pipe,
					struct pipe_buffer *buf,
					struct splice_desc *desc)
{
	struct cachefiles_cx_bitmap *last_bm = NULL;
	struct cachefiles_cache *cache = desc->u.data;
	struct page *page = buf->page;
	unsigned slot, nperpage = cache->cx_nperpage, index;
	size_t size = desc->len;
	int ret;
	u8 *kaddr, *p;
	struct cachefiles_cx_entry *ent;

	_enter(",{%lx},%lx", page->index, size);

	if (size != PAGE_SIZE) {
		_leave(" = -EIO");
		return -EIO;
	}

	index = page->index * nperpage;
	ret = size;

	p = kaddr = kmap_atomic(page);

	for (slot = 0; slot < nperpage; slot++) {
		ent = (struct cachefiles_cx_entry *)p;
		/* The type entry of each slot indicates whether it's occupied
		 * or not (zero indicating unoccupied) */
		if (!ent->type && cachefiles_cx_mark_empty(cache, index + slot,
							   &last_bm) < 0) {
			ret = -EIO;
			break;
		} else if (ent->type) {
			_debug("[%02x]: type=%u len=%u", slot, ent->type, ent->len);
			if (__cachefiles_cx_mark_cullable(cache, index + slot,
							  true, &last_bm) < 0) {
				ret = -EIO;
				break;
			}
		}
		p += cache->cx_entsize;
	}

	kunmap_atomic(kaddr);
	_leave(" = %d", ret);
	return ret;
}

/*
 * First stage actor for page-by-page scanning of the cull index file
 */
static int cachefiles_cx_generate_actor_0(struct pipe_inode_info *pipe,
					  struct splice_desc *desc)
{
	return __splice_from_pipe(pipe, desc, cachefiles_cx_generate_actor);
}

/*
 * scan the index file and generate an in-memory bitmap with a bit set for each
 * empty slot in the index
 */
int cachefiles_cx_generate_bitmap(struct cachefiles_cache *cache)
{
	struct splice_desc desc;
	int ret;

	_enter("");

	/* determine cx_entsize and the per-page density */
	ret = cachefiles_cx_check_size(cache);
	if (ret < 0)
		goto error;

	/* create a number of nodes based on the size of the index file */
	ret = cachefiles_cx_alloc_bitmap(cache);
	if (ret < 0)
		goto error;

	/* scan the index file and build up a bitmap */
	memset(&desc, 0, sizeof(desc));
	desc.total_len = i_size_read(file_inode(cache->cull_index));
	desc.u.data = cache;
	_debug("begin scan");
	ret = splice_direct_to_actor(cache->cull_index, &desc,
				     cachefiles_cx_generate_actor_0);
	_debug("end scan");
	if (ret < 0)
		goto error_free;

	_leave(" = 0");
	return 0;

error_free:
	cachefiles_cx_free_bitmap(cache);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * extend the cull index
 */
static int cachefiles_cx_extend(struct cachefiles_cache *cache)
{
	struct cachefiles_cx_bitmap *bm, *new_bm;
	struct rb_node *p, **insert;
	unsigned long size, nslots, newslots, *bits;
	int ret, loop, stop;

	_enter("");

	down_write(&cache->cull_file_sem);

	nslots = cache->cull_nslots;
	nslots += cache->cx_nperpage;

	/* first expand the atimes file */
	size = nslots * 4;
	ret = vfs_file_truncate(cache->cull_atimes, size, 1);
	if (ret < 0)
		goto io_error;

	/* then expand the index file */
	size = (nslots / cache->cx_nperpage) << PAGE_SHIFT;
	ret = vfs_file_truncate(cache->cull_index, size, 1);
	if (ret < 0)
		goto io_error;

	/* add a new bitmap if necessary */
	spin_lock(&cache->cull_bitmap_lock);

	p = rb_last(&cache->cull_bitmap);
	if (p) {
		bm = rb_entry(p, struct cachefiles_cx_bitmap, rb);
		insert = &p->rb_right;
	} else {
		bm = NULL;
		insert = &cache->cull_bitmap.rb_node;
	}

	/* we need to add a new bitmap if we don't actually have any bitmaps
	 * yet or if the additional page in the index goes past the last bitmap
	 * we do have */
	if (!p || bm->nslots + cache->cx_nperpage > SLOTS_PER_BITMAP) {
		if (bm)
			_debug("- new bm [%u + %u > %lu]",
			       bm->nslots, cache->cx_nperpage,
			       SLOTS_PER_BITMAP);
		else
			_debug("- new bm");
		spin_unlock(&cache->cull_bitmap_lock);

		new_bm = kmalloc(sizeof(*new_bm), GFP_KERNEL);
		if (!new_bm)
			goto error;
		new_bm->free_slots = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!new_bm->free_slots) {
			kfree(new_bm);
			goto error;
		}
		new_bm->cullable_slots = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!new_bm->cullable_slots) {
			put_page(new_bm->free_slots);
			kfree(new_bm);
			goto error;
		}
		spin_lock(&cache->cull_bitmap_lock);
		new_bm->offset = p ? bm->offset + 1 : 0;
		new_bm->nfreeslots = 0;
		new_bm->nslots = 0;

		/* barring the first, we only ever add a node at offset + 1 of
		 * the last node we added */
		rb_link_node(&new_bm->rb, p, insert);
		rb_insert_color(&new_bm->rb, &cache->cull_bitmap);

		if (!p || bm->nslots == SLOTS_PER_BITMAP) {
			bm = new_bm;
			new_bm = NULL;
		}
	} else {
		new_bm = NULL;
	}

	/* we need to record the free slots that we've allocated on disk - we
	 * have to take care, though, as the free slots may span more than one
	 * bitmap */
	newslots = cache->cx_nperpage;
	do {
		_debug("- clear bit ns=%lu", newslots);

		ASSERT(bm != NULL);
		loop = bm->nslots;
		stop = min(loop + newslots, SLOTS_PER_BITMAP);
		newslots -= stop - loop;
		bm->nslots += stop - loop;
		bm->nfreeslots += stop - loop;
		bits = kmap_atomic(bm->free_slots);
		do {
			__set_bit(loop, bits);
		} while (++loop < stop);
		kunmap_atomic(bits);
		bm = new_bm;
	} while (newslots > 0);

	cache->cull_nslots += cache->cx_nperpage;

	spin_unlock(&cache->cull_bitmap_lock);

error:
	up_write(&cache->cull_file_sem);
	_leave(" = %d", ret);
	return ret;

io_error:
	if (ret == -EIO)
		cachefiles_io_error(cache, "Expand index failed");
	goto error;
}

/*
 * allocate a culling index slot for an object
 */
static int cachefiles_cx_alloc_slot(struct cachefiles_cache *cache,
				    struct cachefiles_object *object,
				    unsigned *_slot)
{
	struct cachefiles_cx_bitmap *bm;
	struct rb_node *p;
	unsigned long *bits;
	unsigned slot;
	int ret;

	_enter("");

	ASSERTCMP(object->cull_slot, ==, UINT_MAX);

try_again:
	spin_lock(&cache->cull_bitmap_lock);

	/* first of all, we need to scan the bitmap looking for free slots in
	 * what we've already got */
	for (p = rb_first(&cache->cull_bitmap); p; p = rb_next(p)) {
		bm = rb_entry(p, struct cachefiles_cx_bitmap, rb);
		if (bm->nfreeslots > 0)
			goto allocate_from_this_bitmap;
	}

	/* no spare slots, so we need to allocate some more */
	spin_unlock(&cache->cull_bitmap_lock);
	ret = cachefiles_cx_extend(cache);
	if (ret < 0) {
		_leave(" = %d [extend]", ret);
		return ret;
	}
	goto try_again;

allocate_from_this_bitmap:
	_debug("alloc from bitmap %x [space=%u/%u]",
	       bm->offset, bm->nfreeslots, bm->nslots);

	/* locate and mark the first unused slot as now being in use */
	bits = kmap_atomic(bm->free_slots);
	slot = find_first_bit(bits, SLOTS_PER_BITMAP);
	_debug("FFB [%lx%lx] -> %u", bits[0], bits[1], slot);
	ASSERTCMP(slot, <, SLOTS_PER_BITMAP);
	__clear_bit(slot, bits);
	kunmap_atomic(bits);
	bm->nfreeslots--;
	slot += bm->offset << ilog2(SLOTS_PER_BITMAP);

	spin_unlock(&cache->cull_bitmap_lock);

	*_slot = slot;
	_leave(" = 0 [slot %u]", slot);
	return 0;
}

/*
 * unallocate a culling index slot for an object
 */
void cachefiles_cx_unalloc_slot(struct cachefiles_cache *cache,
				unsigned slot)
{
	struct cachefiles_cx_bitmap *last_bm = NULL;
	int ret;

	_enter(",{%u}", slot);

	if (slot == CACHEFILES_NO_CULL_SLOT ||
	    slot == CACHEFILES_PINNED)
		return;

	spin_lock(&cache->cull_bitmap_lock);

	ret = cachefiles_cx_mark_empty(cache, slot, &last_bm);
	if (ret < 0) {
		printk(KERN_ERR "CacheFiles:"
		       " Culling bitmap [0..%lu] does not include slot %u\n",
		       cache->cull_nslots - 1, slot);
		BUG();
	}

	spin_unlock(&cache->cull_bitmap_lock);
	_leave("");
}

/*
 * clear and unallocate an object's culling index slot
 */
void cachefiles_cx_clear_slot(struct cachefiles_cache *cache,
			      unsigned slot)
{
	mm_segment_t old_fs;
	unsigned offset;
	ssize_t ret;
	loff_t pos, apos;

	_enter(",{%u}", slot);

	if (slot == CACHEFILES_NO_CULL_SLOT ||
	    slot == CACHEFILES_PINNED)
		return;

	/* we write zero bytes over the index type and length */
	pos = slot / cache->cx_nperpage;
	offset = slot % cache->cx_nperpage;
	pos *= PAGE_SIZE;
	pos += offset * cache->cx_entsize;
	apos = slot * sizeof(__le32);

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	_debug("CLEAR index 1 @ %llx", pos);
	ret = cache->cull_index->f_op->write(
		cache->cull_index,
		(const void __user *) empty_zero_page, 2, &pos);
	if (ret != 2)
		goto ioerror;

	ret = cache->cull_atimes->f_op->write(
		cache->cull_atimes,
		(const void __user *) empty_zero_page, sizeof(__le32), &apos);
	if (ret != sizeof(__le32))
		goto ioerror;

	set_fs(old_fs);
	cachefiles_cx_unalloc_slot(cache, slot);

	_leave("");
	return;

ioerror:
	set_fs(old_fs);
	cachefiles_io_error(cache,
			    "Cull index slot %u clearance error: %ld",
			    slot, ret);
}

/*
 * get a culling slot for this object if we don't already have one, or validate
 * the extant one if we do
 * - marks the obtained slot non-cullable before it returns
 */
int cachefiles_cx_get_slot(struct cachefiles_cache *cache,
			   struct cachefiles_object *object,
			   __le32 *slot_from_xattr)
{
	struct cachefiles_cx_entry *entry;
	enum fid_type type;
	mm_segment_t old_fs;
	unsigned slot, offset;
	ssize_t read, written;
	loff_t pos, tmppos;
	void *fh;
	int ret, len;

	_enter(",{%d},%d", object->cull_slot, *slot_from_xattr);

	ASSERTCMP(object->cull_slot, ==, CACHEFILES_NO_CULL_SLOT);

	if (le32_to_cpu(*slot_from_xattr) == CACHEFILES_PINNED) {
		object->cull_slot = le32_to_cpu(*slot_from_xattr);
		_leave(" = 0 [pinned]");
		return 0;
	}

	entry = kmalloc(cache->cx_entsize, GFP_NOIO);
	if (!entry)
		return -ENOMEM;

	fh = kmalloc(NFS4_FHSIZE, GFP_NOIO);
	if (!fh) {
		kfree(entry);
		return -ENOMEM;
	}

	/* get the FH for the backing object */
	len = NFS4_FHSIZE / sizeof(u32);
	type = exportfs_encode_fh(object->dentry, fh, &len, 1);
	if (type == 0xff) {
		cachefiles_io_error(cache,
				    "Can't get FH for backing object %lx",
				    object->dentry->d_inode->i_ino);
		goto io_error_no_setfs;
	}
	/* convert len back to length in bytes */
	len *= sizeof(__be32);

	old_fs = get_fs();
	set_fs(KERNEL_DS);

actually_alloc:
	/* if there's a slot recorded in the object's xattr, then we need to
	 * check it; otherwise we need to allocate a new one and check that */
	slot = le32_to_cpu(*slot_from_xattr);
	if (slot == CACHEFILES_NO_CULL_SLOT) {
		ret = cachefiles_cx_alloc_slot(cache, object, &slot);
		if (ret < 0) {
			cachefiles_io_error(cache,
					    "Failed to alloc cull slot: %d",
					    ret);
			goto io_error_no_unalloc;
		}
	}

	pos = slot / cache->cx_nperpage;
	offset = slot % cache->cx_nperpage;
	pos *= PAGE_SIZE;
	pos += offset * cache->cx_entsize;

	/* read the contents of the slot so that we can check it */
	tmppos = pos;
	read = cache->cull_index->f_op->read(
		cache->cull_index, (void * __user) entry,
		cache->cx_entsize, &tmppos);
	if (read != cache->cx_entsize) {
		cachefiles_io_error(cache,
				    "Cull index slot %d fill check error: %ld",
				    object->cull_slot, read);
		goto io_error;
	}

	if (le32_to_cpu(*slot_from_xattr) == CACHEFILES_NO_CULL_SLOT) {
		/* we've allocated a new slot, which should be unused (we
		 * steal it if not) */
		if (entry->type != 0)
			printk(KERN_WARNING "CacheFiles:"
			       " Unused cull index slot %d in use"
			       " [type %u len %u]\n",
			       slot, entry->type, entry->len);
		entry->type = type;
		entry->len = len;
		memcpy(entry->fh, fh, len);

		/* overwrite the contents of the slot
		 * - we just decide not to care if the slot is already occupied
		 */
		tmppos = pos;
		written = cache->cull_index->f_op->write(
			cache->cull_index, (const void * __user) entry,
			cache->cx_entsize, &tmppos);

		if (written != cache->cx_entsize) {
			cachefiles_io_error(
				cache, "Cull index slot %u fill error: %ld",
				object->cull_slot, written);
			goto io_error;
		}

	} else {
		/* we've got an old slot, which should carry the correct FH */
		if (entry->type != type || entry->len != len ||
		    memcmp(entry->fh, fh, len) != 0) {
			/* doesn't match: forget it and allocate a new slot;
			 * cachefilesd will recycle it eventually if it's
			 * unused */
			printk(KERN_WARNING "CacheFiles:"
			       " Assigned cull index slot %d has wrong FH"
			       " [%u/%u vs %u/%u]\n",
			       slot, entry->type, entry->len, type, len);
			*slot_from_xattr = cpu_to_le32(CACHEFILES_NO_CULL_SLOT);
			goto actually_alloc;
		}
	}

	set_fs(old_fs);
	if (object->cull_slot == CACHEFILES_NO_CULL_SLOT) {
		object->cull_slot = slot;
		if (*slot_from_xattr != cpu_to_le32(slot)) {
			*slot_from_xattr = cpu_to_le32(slot);
			__set_bit(CACHEFILES_OBJECT_UPDATE_XATTR,
				  &object->flags);
		}
	}

	cachefiles_cx_mark_cullable(cache, slot, false);

	kfree(fh);
	kfree(entry);
	_leave(" = 0 [slot %d]", object->cull_slot);
	return 0;

io_error:
	if (object->cull_slot != CACHEFILES_NO_CULL_SLOT) {
		cachefiles_cx_unalloc_slot(cache, object->cull_slot);
		object->cull_slot = CACHEFILES_NO_CULL_SLOT;
	}
io_error_no_unalloc:
	set_fs(old_fs);
io_error_no_setfs:
	kfree(fh);
	kfree(entry);
	return -EIO;
}

/*
 * note the time of an access of an object in the cull index
 */
void cachefiles_cx_mark_access(struct cachefiles_cache *cache,
			       struct cachefiles_object *object)
{
	mm_segment_t old_fs;
	ssize_t ret;
	time_t atime;
	loff_t pos;
	__le32 buffer;
	u32 ratime;

	_enter(",{%u}", object->cull_slot);

	if (object->cull_slot == UINT_MAX)
		return;

	atime = get_seconds();
	/* Reserve 0 to indicate an empty slot, so ensure ratime is non-zero. */
	ratime = atime > cache->atime_base ? atime - cache->atime_base : 1;
	buffer = cpu_to_le32(ratime);

	pos = object->cull_slot;
	pos *= 4;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = cache->cull_atimes->f_op->write(
		cache->cull_atimes, (const void __user *) &buffer, 4, &pos);
	set_fs(old_fs);

	if (ret != 4) {
		object->cull_slot = UINT_MAX;
		cachefiles_io_error(cache,
				    "Cull index slot %u mark error: %ld",
				    object->cull_slot, ret);
		return;
	}

	_leave("");
	return;
}

/*
 * exportfs decode check
 */
static int cachefiles_cx_lookup_acceptable(void *context, struct dentry *dentry)
{
	return true;
}

/*
 * look up an entry in the culling index
 */
int cachefiles_cx_lookup(struct cachefiles_cache *cache,
			 unsigned slot,
			 struct dentry **_dir,
			 struct dentry **_object)
{
	struct cachefiles_cx_entry *entry;
	struct dentry *dir, *dentry;
	mm_segment_t old_fs;
	unsigned offset;
	ssize_t read;
	void *buffer;
	loff_t pos;
	int ret;

	_enter(",{%u},,", slot);

	/* firstly we need to read the entry from the index (making sure the FH
	 * is 32-bit aligned) */
	buffer = kmalloc(cache->cx_entsize + 2, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;
	entry = buffer + 2;

	pos = slot / cache->cx_nperpage;
	offset = slot % cache->cx_nperpage;
	pos *= PAGE_SIZE;
	pos += offset * cache->cx_entsize;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	read = cache->cull_index->f_op->read(cache->cull_index,
					     (void * __user) entry,
					     cache->cx_entsize, &pos);
	set_fs(old_fs);

	if (read != cache->cx_entsize) {
		cachefiles_io_error(cache,
				    "Cull index slot %d read error: %ld",
				    slot, read);
		kfree(buffer);
		return -EIO;
	}

	/* check that the slot is occupied */
	if (entry->type == 0) {
		kfree(buffer);
		kleave(" = -ESTALE [unoccupied]");
		return -ESTALE;
	}

	/* ask exportfs to interpret the FH */
	dentry = exportfs_decode_fh(cache->mnt, (struct fid *) entry->fh,
				    entry->len, entry->type,
				    cachefiles_cx_lookup_acceptable, NULL);
	kfree(buffer);
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		if (ret == -ESTALE) {
			kleave(" = -ESTALE [unresolvable]");
			return -ESTALE;
		}
		pr_err("Cannot decode cull slot %d FH: %d", slot, ret);
		return -EIO;
	}

	if (IS_ROOT(dentry)) {
		dput(dentry);
		pr_err("Cannot find parent of file in cull slot %d FH", slot);
		return -ESTALE;
	}

	dir = dget_parent(dentry);

	_debug("cull slot %d: %*.*s/%*.*s",
	       slot,
	       dir->d_name.len, dir->d_name.len, dir->d_name.name,
	       dentry->d_name.len, dentry->d_name.len, dentry->d_name.name);

	*_dir = dir;
	*_object = dentry;
	kleave(" = 0");
	return 0;
}

/*
 * validate a cull slot
 */
int cachefiles_cx_validate_slot(struct cachefiles_cache *cache,
				struct dentry *dentry,
				unsigned slot)
{
	struct cachefiles_cx_entry *entry;
	enum fid_type type;
	mm_segment_t old_fs;
	unsigned offset;
	ssize_t read;
	loff_t pos;
	void *fh;
	int ret, len;

	_enter(",,%d", slot);

	if (slot == CACHEFILES_NO_CULL_SLOT)
		return -ENOENT;

	if (slot > cache->cull_nslots)
		return -ENOENT;

	entry = kmalloc(cache->cx_entsize, GFP_NOIO);
	if (!entry)
		return -ENOMEM;

	fh = kmalloc(NFS4_FHSIZE, GFP_NOIO);
	if (!fh) {
		kfree(entry);
		return -ENOMEM;
	}

	pos = slot / cache->cx_nperpage;
	offset = slot % cache->cx_nperpage;
	pos *= PAGE_SIZE;
	pos += offset * cache->cx_entsize;

	/* read the contents of the slot so that we can check it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	read = cache->cull_index->f_op->read(
		cache->cull_index, (void * __user) entry,
		cache->cx_entsize, &pos);
	set_fs(old_fs);

	if (read != cache->cx_entsize) {
		cachefiles_io_error(cache,
				    "Cull index slot %d read error: %ld",
				    slot, read);
		goto io_error;
	}

	if (entry->type == 0) {
		/* the slot not in use */
		ret = -ESTALE;
		goto out;
	}		

	/* get the FH for the backing object */
	len = NFS4_FHSIZE / sizeof(u32);
	type = exportfs_encode_fh(dentry, fh, &len, 1);
	if (type == 0xff) {
		cachefiles_io_error(cache,
				    "Can't get FH for backing object %lx",
				    dentry->d_inode->i_ino);
		goto io_error;
	}

	/* we've got an old slot, which should carry the correct FH */
	if (entry->type != type || entry->len != len ||
	    memcmp(entry->fh, fh, len) != 0) {
		/* doesn't match */
		printk(KERN_WARNING "CacheFiles:"
		       " Assigned cull index slot %d has wrong FH"
		       " [%u/%u vs %u/%u]\n",
		       slot, entry->type, entry->len, type, len);
		ret = -ESTALE;
	} else {
		ret = 0;
	}

out:
	kfree(fh);
	kfree(entry);
	_leave(" = %d", ret);
	return ret;

io_error:
	kfree(fh);
	kfree(entry);
	return -EIO;
}


/**
 * repair a slot if the file it points to is not in use.
 * If the file is in use, it was re-assigned a new slot
 * by cachefiles_cx_get_slot, so delete this old duplicated slot.
 *
 * @return 0 on success, negative integer otherwise.
 */
int cachefiles_cx_fixslot(struct cachefiles_cache *cache, unsigned slot)
{
	struct dentry *dir, *entry;
	int ret = 0;

	_enter("%p,%u",cache,slot);

	/* Look up the slot requested. The FH _shouldn't_ be stale,
	 * because the daemon identified this as a slot to 'fix'. */
	ret = cachefiles_cx_lookup(cache, slot, &dir, &entry);
	if (unlikely(ret < 0)) {
		if (ret == -ESTALE) {
			cachefiles_cx_clear_slot(cache, slot);
			ret = 0;
		}
		goto leave;
	}

	_debug("fixslot %*.*s/%*.*s",
	       dir->d_name.len, dir->d_name.len, dir->d_name.name,
	       entry->d_name.len, entry->d_name.len, entry->d_name.name);

	mutex_lock_nested(&dir->d_inode->i_mutex, 1);
	/* We take a lock that assures us that the code responsible
	 * for bringing new items into the cache will not be able to
	 * read xattrs or mark an object as active. */
	mutex_lock(&cache->xattr_mutex);

	/*
	 * Check if the entry is in use or not.
	 * Note that a dentry is marked active _after_ it reads the xattr from disk.
	 *
	 * If the file is not active, thanks to the xattr_mutex, it will not
	 * BECOME active until after we release the lock -- this means that
	 * the xattrs definitely have not been read into memory yet. We can
	 * therefore fix the xattr on the file itself.
	 *
	 * If the file is already active, it was _definitely_ given a new slot,
	 * so we should just clear this slot instead, as a duplicate.
	 */
	ret = cachefiles_check_dentry_active(cache, dir, entry);
	if (ret < 0) {
		if (ret == -EBUSY) {
			_debug("- fixslot, file in use, deleting slot");
			cachefiles_cx_clear_slot(cache, slot);
			ret = 0;
		} else {
			pr_err("Error checking if file (%s) is active",
			       entry->d_name.name);
		}
		goto unlock;
	}

	/* Okay, dentry wasn't active. */
	ret = cachefiles_reset_slot(entry, slot);
	if (ret < 0) {
		pr_err("fixslot: failed to reset slot to %u", slot);
		goto unlock;
	}

unlock:
	mutex_unlock(&dir->d_inode->i_mutex);
	mutex_unlock(&cache->xattr_mutex);
leave:
	_leave(" = %d", ret);
	return ret;
}
