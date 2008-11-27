/*
 * Copyright (C) 2008 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/pagemap.h>
#include <linux/acall.h>

/*
 * The following must be fixed before merging:
 *
 * - Add a timeout value to sys_acall_wait();
 *
 * - Add a signal specifier to struct acall_submission so that acall_thread
 * can send a signal as the operation completes.  The same goes for a 
 * signalfd.
 *
 * - Make sure that there is a limit to the number of threads which can be
 * created.  Hopefully RLIMIT_NPROC will be good enough.
 *
 * - Create per-arch helpers to call the syscalls.
 *
 * - Figure out what to do if acall_thread() can't write completion to
 * userspace.  Do we segfault?  Just ignore it?
 *
 * Here are some ideas for additional functionality:
 *
 * - Add a flag to specify that the operation should follow syslet semantics.
 * That is, that the new child returns to userspace when the submitting
 * context blocks.
 *
 * - Add a flag to specify that all the operations should be processed as 
 * concurrently as possible.
 *
 * - Coordinate with the scheduler so that sys_acall_submit() only proceeds
 * once acall_thread() blocks during processing.
 *
 * - Add a flag to put timestamps in acall_result.
 */
struct acall_results {
	spinlock_t lock;
	struct acall_result __user *results;
	unsigned long done;
	unsigned long total;
};

struct acall_thread_args {
	struct completion completion;
	struct acall_submission sub;
	struct acall_results *res;
};

/*
 * We need to associate a userspace pointer with a wait queue so that
 * acall_thread() can wake tasks which are blocked in sys_acall_wait().
 *
 * We could do it with our own hashed wait queues.  We'd be recreating all the
 * problems that the hashed waitqueues in the zone already worry about --
 * contention, cache footprint, sizing to the system, etc.
 *
 * And further, it'd be perfectly legal for a task to be watching a result
 * structure which is mapped in shared memory at an address that is different
 * than the one that the completing task is writing to.  We'd work with this by
 * hashing by the low bits of the address.  Then we'd be limited to PAGE_SIZE /
 * sizeof(struct acall_result) = 256 hash buckets.
 *
 * Instead we resolve the result pointer down to the page struct that backs it
 * and hash that into the zone's wait queues.
 * We're trading scalability
 * for some page handling overhead in the completion path.  Ideally this will
 * almost always be cached and won't be a big deal. 
 *
 * The sleeper pins the page while it is asleep to make sure that the page
 * that backs the address doesn't change from under it while it sleeps.  IF
 * it did the waker would hash to a different wait queue and we'd miss
 * an event.
 */
static struct page *pin_page(unsigned long addr)
{
	struct page *page;
	int ret;

	ret = get_user_pages(current, current->mm, addr, 1, 0, 0, &page, NULL);
	if (ret < 0)
		return ERR_PTR(ret);

	BUG_ON(ret != 1);
	return page;
}

static void unlock_res_might_free(struct acall_results *res)
__releases(res->lock)
{
	assert_spin_locked(&res->lock);
	BUG_ON(res->done > res->total);
	if (res->done == res->total) {
		spin_unlock(&res->lock);
		kfree(res);
	} else
		spin_unlock(&res->lock);
}

static struct acall_result __user *next_result(struct acall_results *res)
{
	struct acall_result __user *ret;

	spin_lock(&res->lock);
	ret = &res->results[res->done];
	res->done++;
	unlock_res_might_free(res);

	return ret;
}

/* XXX */
static long call_syscall(struct acall_submission *sub)
{
	typedef asmlinkage long (*syscall_fn_t)(long, long, long, long, long,
						long);
	extern syscall_fn_t sys_call_table[];

	if (sub->nr >= 290) /* hee, x86-64 */
		return -ENOSYS;
	else
		return sys_call_table[sub->nr](sub->args[0], sub->args[1],
					       sub->args[2], sub->args[3],
					       sub->args[4], sub->args[5]);
};

static int acall_thread(void *data)
{
	struct acall_thread_args *args = data;
	struct acall_result __user *result;
	struct page *page;
	long ret;

	current->acall_cookie = args->sub.cookie;

	wait_for_completion(&args->completion);
	/* see if our parent has told us to skip this op */
	if (args->sub.cookie == 0)
		goto out;

	ret = call_syscall(&args->sub);

	/* res might be freed, don't use it after this */
	result = next_result(args->res);

	ret = __put_user((u64)ret, &result->return_code);
	/* XXX memory barrier so user can test the cookie */
	ret |= __put_user(args->sub.cookie, &result->cookie);

	page = pin_page((unsigned long)&result->cookie);
	if (IS_ERR(page))
		ret |= 1;
	else {
		/* XXX memory barrier for sys_acall_wait? */
		wake_up(page_waitqueue(page));
		put_page(page);
	}

	BUG_ON(ret); /* XXX segfault? */

out:
	kfree(args);
	return 0;
}

/*
 * Submits system calls to be executed by newly created kernel threads.
 *
 * The submissions array contains pointers to submission structures, one
 * for each operation.  The pointer and submission struct are copied to
 * the kernel.
 *
 * Once the operation is started an id for the operation is written into
 * the id field of the operation's submission structure in userspace.  Once
 * that id is written the submission structure will not be referenced by
 * the kernel again.
 *
 * The user provides a cookie to identify the operation.  This must not be zero.
 * Its use by cancellation implies some uniqueness -- see sys_acall_cancel(). 
 *
 * The elements of the results array will be filled in as operations complete.
 * The results elements will be filled in ascending memory order as operations
 * complete.  The operations themselves may complete out of order.  The
 * cookie field of the result structure can be tested to determine if the
 * result has been filled.  This is why the cookie must not be 0 during
 * completion.  Each result structure is zeroed by the kernel as operations
 * are submitted.
 *
 * A positive return code gives the number of operations which are now
 * pending.  That many result structures will be filled in the future.  A
 * return code less than 'nr' is possible if later submissions contain errors.
 */
asmlinkage long sys_acall_submit(struct acall_submission __user **submissions,
				 struct acall_result __user *results,
				 unsigned long nr)
{
	struct acall_submission __user *sub_ptr;
	struct acall_thread_args *args = NULL;
	struct acall_results *res;
	unsigned long i = 0;
	pid_t pid;
	int ret = 0;

	res = kmalloc(sizeof(struct acall_results), GFP_KERNEL);
	if (res == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_init(&res->lock);
	res->results = results;
	res->done = 0;
	res->total = nr;

	for (; i < nr; i++) {
		ret = __put_user((u64)0, &results[i].cookie);
		ret |= __put_user((u64)0, &results[i].return_code);
		if (ret) {
			ret = -EFAULT;
			goto out;
		}

		args = kmalloc(sizeof(struct acall_thread_args), GFP_KERNEL);
		if (args == NULL) {
			ret = -ENOMEM;
			break;
		}

		/* XXX 32 on 64 without giant stack copy */
		if (__get_user(sub_ptr, &submissions[i])) {
			ret = -EFAULT;
			break;
		}

		if (copy_from_user(&args->sub, sub_ptr,
				   sizeof(struct acall_submission))) {
			ret = -EFAULT;
			break;
		}

		if (args->sub.flags || args->sub.cookie == 0 || args->sub.id) {
			ret = -EINVAL;
			break;
		}

		init_completion(&args->completion);
		args->res = res;

		pid = kernel_thread(acall_thread, args,
				CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_IO);
		if (pid < 0) {
			ret = pid;
			break;
		}

		ret = __put_user((u32)pid, &sub_ptr->id);
		if (ret) {
			args->sub.cookie = 0;
			ret = -EFAULT;
		}
		complete(&args->completion);
		args = NULL; /* the thread frees the args struct */
		if (ret)
			break;
	}

	/* update total and free res if that many have already finished */
	if (i != nr) {
		spin_lock(&res->lock);
		res->total = i;
		unlock_res_might_free(res);
	}

	kfree(args);
out:
	return i ? i : ret;
}

static int wait_for_cookie(u64 __user *addr)
{
	struct page *page;
	wait_queue_head_t *wq;
	DEFINE_WAIT(wait);
	u64 cookie;
	int ret;

	do {
#if 0
		if (__get_user(cookie, addr)) {
			ret = -EFAULT;
			break;
		}
#else
		if (__copy_from_user(&cookie, addr, sizeof(addr))) {
			ret = -EFAULT;
			break;
		}
#endif

		if (cookie) {
			ret = 0;
			break;
		}

		page = pin_page((unsigned long)addr);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			break;
		}

		wq = page_waitqueue(page);
		prepare_to_wait(wq, &wait, TASK_UNINTERRUPTIBLE);
		pagefault_disable();
		ret = __copy_from_user_inatomic(&cookie, addr, sizeof(u64));
		pagefault_enable();
		if (ret)
			cookie = 0;
		if (cookie == 0)
			schedule();
		finish_wait(wq, &wait);
		put_page(page);

	} while (cookie == 0);

	return ret;
}

/*
 * Returns the number of contiguous elements from the start of the given result
 * array which have non-zero cookie fields, indicating that an operation has
 * completed.
 *
 * A return code less than 'nr' implies that later results had errors, most
 * likely faulting on the result arrays.  A return code < 0 is the errno
 * of the failure of the first element in the array.
 *
 * Userspace can test the cookie element themselves before calling here to
 * avoid a syscall to discover completed results.
 */
asmlinkage long sys_acall_wait(struct acall_result __user *result,
			       unsigned long nr)
{
	unsigned long i;
	int ret = 0;

	for (i = 0; i < nr; i++) {
		ret = wait_for_cookie(&result[i].cookie);
		if (ret)
			break;
	}

	return i ? i : ret;
}

/*
 * Cancels the operation specified by the given cookie and id.  The id is
 * set by the kernel as the operation begins processing.
 *
 * The cookie is set by the user.  It differentiates between operations
 * that might have been serviced under the same id.  Imagine:
 *
 * cookie:1,id:1 is submitted
 * a cancel for 1:1 starts
 * 1:1 completes
 * another cookie:1 is submitted, and the kernel choses id:1 again
 * cancel 1:1 resumes, and cancels the wrong operation
 *
 * userspace could have avoided this by serializing their completion
 * and cancelation routines.  Or they could provide unique cookies so that
 * the second submission in that example has a cookie that isn't 1.
 *
 * -EAGAIN will be returned if the operation wasn't found or if the target
 * thread doesn't share an mm context with the calling task.
*
 * 0 will be returned if the operation was canceled by successfully sending a
 * signal to the thread processing the operation.  A result structure
 *
 * will be filled in at some point in the future with a return_code whose
 * semantics are entirely up to the system call whose thread caught the signal.
 */
asmlinkage long sys_acall_cancel(u64 cookie, u32 id)
{
	struct task_struct *task;
	int ret = -EAGAIN;

	rcu_read_lock();
	task = pid_task(find_vpid(id), PIDTYPE_PID);
	if (task && task->mm == current->mm && task->acall_cookie == cookie) {
		struct siginfo info;

		info.si_signo = SIGKILL;
		info.si_errno = 0;
		info.si_code = SI_KERNEL;
		info.si_pid = task_tgid_vnr(current);
		info.si_uid = current->uid;

		if (force_sig_info(info.si_signo, &info, task) == 0)
			ret = 0;
	}
	rcu_read_unlock();

	return ret;
}
