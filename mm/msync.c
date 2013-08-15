/*
 *	linux/mm/msync.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * The msync() system call.
 */
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>

/*
 * MS_SYNC syncs the entire file - including mappings.
 *
 * MS_ASYNC does not start I/O (it used to, up to 2.5.67).
 * Nor does it marks the relevant pages dirty (it used to up to 2.6.17).
 * Now all it does is ensure that file timestamps get updated, since POSIX
 * requires it.  We track dirty pages correct without MS_ASYNC.
 *
 * The application may now run fsync() to
 * write out the dirty pages and wait on the writeout and check the result.
 * Or the application may run fadvise(FADV_DONTNEED) against the fd to start
 * async writeout immediately.
 * So by _not_ starting I/O in MS_ASYNC we provide complete flexibility to
 * applications.
 */

static int msync_async_range(struct vm_area_struct *vma,
			      unsigned long *start, unsigned long end)
{
	struct mm_struct *mm;
	int iters = 0;

	while (*start < end && *start < vma->vm_end && iters < 128) {
		unsigned int page_mask, page_increm;

		/*
		 * Require that the pte is writable (because otherwise
		 * it can't be dirty, so there's nothing to clean).
		 *
		 * In theory we could check the pte dirty bit, but this is
		 * awkward and barely worth it.
		 */
		struct page *page = follow_page_mask(vma, *start,
						     FOLL_GET | FOLL_WRITE,
						     &page_mask);

		if (page && !IS_ERR(page)) {
			if (lock_page_killable(page) == 0) {
				page_mkclean(page);
				unlock_page(page);
			}
			put_page(page);
		}

		if (IS_ERR(page))
			return PTR_ERR(page);

		page_increm = 1 + (~(*start >> PAGE_SHIFT) & page_mask);
		*start += page_increm * PAGE_SIZE;
		cond_resched();
		iters++;
	}

	/* XXX: try to do this only once? */
	mapping_flush_cmtime_nowb(vma->vm_file->f_mapping);

	/* Give mmap_sem writers a chance. */
	mm = current->mm;
	up_read(&mm->mmap_sem);
	down_read(&mm->mmap_sem);
	return 0;
}

SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
{
	unsigned long end;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int unmapped_error = 0;
	int error = -EINVAL;

	if (flags & ~(MS_ASYNC | MS_INVALIDATE | MS_SYNC))
		goto out;
	if (start & ~PAGE_MASK)
		goto out;
	if ((flags & MS_ASYNC) && (flags & MS_SYNC))
		goto out;
	error = -ENOMEM;
	len = (len + ~PAGE_MASK) & PAGE_MASK;
	end = start + len;
	if (end < start)
		goto out;
	error = 0;
	if (end == start)
		goto out;
	/*
	 * If the interval [start,end) covers some unmapped address ranges,
	 * just ignore them, but return -ENOMEM at the end.
	 */
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, start);
	for (;;) {
		struct file *file;

		/* Still start < end. */
		error = -ENOMEM;
		if (!vma)
			goto out_unlock;
		/* Here start < vma->vm_end. */
		if (start < vma->vm_start) {
			start = vma->vm_start;
			if (start >= end)
				goto out_unlock;
			unmapped_error = -ENOMEM;
		}
		/* Here vma->vm_start <= start < vma->vm_end. */
		if ((flags & MS_INVALIDATE) &&
				(vma->vm_flags & VM_LOCKED)) {
			error = -EBUSY;
			goto out_unlock;
		}
		file = vma->vm_file;
		if (file && vma->vm_flags & VM_SHARED) {
			if (flags & MS_SYNC) {
				start = vma->vm_end;
				get_file(file);
				up_read(&mm->mmap_sem);
				error = vfs_fsync(file, 0);
				fput(file);
				if (error || start >= end)
					goto out;
				down_read(&mm->mmap_sem);
			} else if ((vma->vm_flags & VM_WRITE) &&
				   file->f_mapping) {
				error = msync_async_range(vma, &start, end);
				if (error || start >= end)
					goto out_unlock;
			} else {
				start = vma->vm_end;
				if (start >= end)
					goto out_unlock;
			}
			vma = find_vma(mm, start);
		} else {
			start = vma->vm_end;
			if (start >= end) {
				error = 0;
				goto out_unlock;
			}
			vma = vma->vm_next;
		}
	}
out_unlock:
	up_read(&mm->mmap_sem);
out:
	return error ? : unmapped_error;
}
