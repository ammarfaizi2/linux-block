#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/syslet.h>

#include <asm/uaccess.h>

/*
 * XXX todo:
 *  - do we need all this '*cur = current' nonsense?
 *  - try to prevent userspace from submitting too much.. lazy user ptr read?
 *  - explain how to deal with waiting threads with stale data in current
 *  - how does userspace tell that a syslet completion was lost?
 *  	provide an -errno argument to the userspace return function?
 */

/*
 * These structs are stored on the kernel stack of tasks which are waiting to
 * return to userspace.  They are linked into their parent's list of syslet
 * children stored in 'syslet_tasks' in the parent's task_struct.
 */
struct syslet_task_entry {
	struct task_struct *task;
	struct list_head item;
};

/*
 * syslet_ring doesn't have any kernel-side storage.  Userspace allocates them
 * in their address space and initializes their fields and then passes them to
 * the kernel.
 *
 * These hashes provide the kernel-side storage for the wait queues which
 * sys_syslet_ring_wait() uses and the mutex which completion uses to serialize
 * the (possible blocking) ordered writes of the completion and kernel head
 * index into the ring.
 *
 * We chose the bucket that supports a given ring by hashing a u32 that
 * userspace sets in the ring.
 */
#define SYSLET_HASH_BITS (CONFIG_BASE_SMALL ? 4 : 8)
#define SYSLET_HASH_NR (1 << SYSLET_HASH_BITS)
#define SYSLET_HASH_MASK (SYSLET_HASH_NR - 1)
static wait_queue_head_t syslet_waitqs[SYSLET_HASH_NR];
static struct mutex syslet_muts[SYSLET_HASH_NR];

static wait_queue_head_t *ring_waitqueue(struct syslet_ring __user *ring)
{
	u32 group;

	if (get_user(group, &ring->wait_group))
		return ERR_PTR(-EFAULT);
	else
		return &syslet_waitqs[jhash_1word(group, 0) & SYSLET_HASH_MASK];
}

static struct mutex *ring_mutex(struct syslet_ring __user *ring)
{
	u32 group;

	if (get_user(group, (u32 __user *)&ring->wait_group))
		return ERR_PTR(-EFAULT);
	else
		return &syslet_muts[jhash_1word(group, 0) & SYSLET_HASH_MASK];
}

/*
 * This is called for new tasks and for child tasks which might copy
 * task_struct from their parent.  So we clear the syslet indirect args,
 * too, just to be clear.
 */
void syslet_init(struct task_struct *tsk)
{
	memset(&tsk->indirect_params.syslet, 0, sizeof(struct syslet_args));
	spin_lock_init(&tsk->syslet_lock);
	INIT_LIST_HEAD(&tsk->syslet_tasks);
	tsk->syslet_ready = 0;
	tsk->syslet_return = 0;
	tsk->syslet_exit = 0;
}

static struct task_struct *first_syslet_task(struct task_struct *parent)
{
	struct syslet_task_entry *entry;

	assert_spin_locked(&parent->syslet_lock);

	if (!list_empty(&parent->syslet_tasks)) {
		entry = list_first_entry(&parent->syslet_tasks,
					 struct syslet_task_entry, item);
		return entry->task;
	} else
		return NULL;
}

/*
 * XXX it's not great to wake up potentially lots of tasks under the lock
 */
/*
 * We ask all the waiting syslet tasks to exit before we ourselves will
 * exit.  The tasks remove themselves from the list and wake our process
 * with the lock held to be sure that we're still around when they wake us.
 */
void kill_syslet_tasks(struct task_struct *cur)
{
	struct syslet_task_entry *entry;

	spin_lock(&cur->syslet_lock);

	list_for_each_entry(entry, &cur->syslet_tasks, item)  {
		entry->task->syslet_exit = 1;
		wake_up_process(entry->task);
	}

	while (!list_empty(&cur->syslet_tasks)) {
		set_task_state(cur, TASK_INTERRUPTIBLE);
		if (list_empty(&cur->syslet_tasks))
			break;
		spin_unlock(&cur->syslet_lock);
		schedule();
		spin_lock(&cur->syslet_lock);
	}
	spin_unlock(&cur->syslet_lock);

	set_task_state(cur, TASK_RUNNING);
}

/*
 * This task is cloned off of a syslet parent as the parent calls
 * syslet_pre_indirect() from sys_indirect().  That parent waits for us to
 * complete a completion struct on their stack.
 *
 * This task then waits until its parent tells it to return to user space on
 * its behalf when the parent gets in to schedule().
 *
 * The parent in schedule will set this tasks's ptregs frame to return to the
 * sys_indirect() call site in user space.  Our -ESYSLETPENDING return code is
 * given to userspace to indicate that the status of their system call
 * will be delivered to the ring.
 */
struct syslet_task_args {
	struct completion *comp;
	struct task_struct *parent;
};
static long syslet_thread(void *data)
{
	struct syslet_task_args args;
	struct task_struct *cur = current;
	struct syslet_task_entry entry = {
		.task = cur,
		.item = LIST_HEAD_INIT(entry.item),
	};

	args = *(struct syslet_task_args *)data;

	spin_lock(&args.parent->syslet_lock);
	list_add_tail(&entry.item, &args.parent->syslet_tasks);
	spin_unlock(&args.parent->syslet_lock);

	complete(args.comp);

	/* wait until the scheduler tells us to return to user space */
	for (;;) {
		set_task_state(cur, TASK_INTERRUPTIBLE);
		if (cur->syslet_return || cur->syslet_exit ||
		    signal_pending(cur))
			break;
		schedule();
	}
	set_task_state(cur, TASK_RUNNING);

	spin_lock(&args.parent->syslet_lock);
	list_del(&entry.item);
	/* our parent won't exit until it tests the list under the lock */
	if (list_empty(&args.parent->syslet_tasks))
		wake_up_process(args.parent);
	spin_unlock(&args.parent->syslet_lock);

	/* just exit if we weren't asked to return to userspace */
	if (!cur->syslet_return)
		do_exit(0);

	/* inform userspace that their call will complete in the ring */
	return -ESYSLETPENDING;
}

static int create_new_syslet_task(struct task_struct *cur)
{
	struct syslet_task_args args;
	struct completion comp;
	int ret;

	init_completion(&comp);
	args.comp = &comp;
	args.parent = cur;

	ret = create_syslet_thread(syslet_thread, &args,
				   CLONE_VM | CLONE_FS | CLONE_FILES |
				   CLONE_SIGHAND | CLONE_THREAD |
				   CLONE_SYSVSEM);
	if (ret >= 0) {
		wait_for_completion(&comp);
		ret = 0;
	}

	return ret;
}

/*
 * This is called by sys_indirect() when it sees that syslet args have
 * been provided.  We validate the arguments and make sure that there is
 * a task waiting.  If everything works out we tell the scheduler that it
 * can call syslet_schedule() by setting syslet_ready.
 */
int syslet_pre_indirect(void)
{
	struct task_struct *cur = current;
	struct syslet_ring __user *ring;
	u32 elements;
	int ret;

	/* Not sure if returning -EINVAL on unsupported archs is right */
	if (!syslet_frame_valid(&cur->indirect_params.syslet.frame)) {
		ret = -EINVAL;
		goto out;
	}

	ring = (struct syslet_ring __user __force *)(unsigned long)
		cur->indirect_params.syslet.completion_ring_ptr;
	if (get_user(elements, &ring->elements)) {
		ret = -EFAULT;
		goto out;
	}

	if (!is_power_of_2(elements)) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * Racing to test this list outside the lock as the final task removes
	 * itself is OK.  It should be very rare, and all it results in is
	 * syslet_schedule() finding the list empty and letting the task block.
	 */
	if (list_empty(&cur->syslet_tasks)) {
		ret = create_new_syslet_task(cur);
		if (ret)
			goto out;
	} else
		ret = 0;

	cur->syslet_ready = 1;
out:
	return ret;
}

/*
 * This is called by sys_indirect() after it has called the given system
 * call handler.  If we didn't block then we just return the status of the
 * system call to userspace.
 *
 * If we did bock, however, then userspace got a -ESYSLETPENDING long ago.
 * We need to deliver the status of the system call into the syslet ring
 * and then return to the function in userspace which the caller specified
 * in the frame in the syslet args.  schedule() already set that up
 * when we blocked.  All we have to do is return to userspace.
 *
 * The return code from this function is lost.  It could become the
 * argument to the userspace return function which would let us tell
 * userspace when we fail to copy the status into the ring.
 */
int syslet_post_indirect(int status)
{
	struct syslet_ring __user *ring;
	struct syslet_completion comp;
	struct task_struct *cur = current;
	struct syslet_args *args = &cur->indirect_params.syslet;
	wait_queue_head_t *waitq;
	struct mutex *mutex;
	u32 kidx;
	u32 mask;
	int ret;

	/* we didn't block, just return the status to userspace */
	if (cur->syslet_ready) {
		cur->syslet_ready = 0;
		return status;
	}

	ring = (struct syslet_ring __force __user *)(unsigned long)
		args->completion_ring_ptr;

	comp.status = status;
	comp.caller_data = args->caller_data;

	mutex = ring_mutex(ring);
	if (IS_ERR(mutex))
		return PTR_ERR(mutex);

	waitq = ring_waitqueue(ring);
	if (IS_ERR(waitq))
		return PTR_ERR(waitq);

	if (get_user(mask, &ring->elements))
		return -EFAULT;

	if (!is_power_of_2(mask))
		return -EINVAL;
	mask--;

	mutex_lock(mutex);

	ret = -EFAULT;
	if (get_user(kidx, (u32 __user *)&ring->kernel_head))
		goto out;

	if (copy_to_user(&ring->comp[kidx & mask], &comp, sizeof(comp)))
		goto out;

	/*
	 * Make sure that the completion is stored before the index which
	 * refers to it.  Notice that this means that userspace has to worry
	 * about issuing a read memory barrier after it reads the index.
	 */
	smp_wmb();

	kidx++;
	if (put_user(kidx, &ring->kernel_head))
		ret = -EFAULT;
	else
		ret = 0;
out:
	mutex_unlock(mutex);
	if (ret == 0 && waitqueue_active(waitq))
		wake_up(waitq);
	return ret;
}

/*
 * We're called by the scheduler when it sees that a task is about to block and
 * has syslet_ready.  Our job is to hand userspace's state off to a waiting
 * task and tell it to return to userspace.  That tells userspace that the
 * system call that we're executing blocked and will complete in the future.
 *
 * The indirect syslet arguemnts specify the userspace instruction and stack
 * that the child should return to.
 */
void syslet_schedule(struct task_struct *cur)
{
	struct task_struct *child = NULL;

	spin_lock(&cur->syslet_lock);

	child = first_syslet_task(cur);
	if (child) {
		move_user_context(child, cur);
		set_user_frame(cur, &cur->indirect_params.syslet.frame);
		cur->syslet_ready = 0;
		child->syslet_return = 1;
	}

	spin_unlock(&cur->syslet_lock);

	if (child)
		wake_up_process(child);
}

/*
 * Userspace calls this when the ring is empty.  We return to userspace
 * when the kernel head and user tail indexes are no longer equal, meaning
 * that the kernel has stored a new completion.
 *
 * The ring is stored entirely in user space.  We don't have a system call
 * which initializes kernel state to go along with the ring.
 *
 * So we have to read the kernel head index from userspace.  In the common
 * case this will not fault or block and will be a very fast simple
 * pointer dereference.
 *
 * Howerver, we need a way for the kernel completion path to wake us when
 * there is a new event.  We hash a field of the ring into buckets of
 * wait queues for this.
 *
 * This relies on aligned u32 reads and writes being atomic with regard
 * to other reads and writes, which I sure hope is true on linux's
 * architectures.  I'm crossing my fingers.
 */
asmlinkage long sys_syslet_ring_wait(struct syslet_ring __user *ring,
				     unsigned long user_idx)
{
	wait_queue_head_t *waitq;
	struct task_struct *cur = current;
	DEFINE_WAIT(wait);
	u32 kidx;
	int ret;

	/* XXX disallow async waiting */

	waitq = ring_waitqueue(ring);
	if (IS_ERR(waitq)) {
		ret = PTR_ERR(waitq);
		goto out;
	}

	/*
	 * We have to be careful not to miss wake-ups by setting our
	 * state before testing the condition.  Testing our condition includes
	 * copying the index from userspace, which can modify our state which
	 * can mask a wake-up setting our state.
	 *
	 * So we very carefully copy the index.  We use the blocking copy
	 * to fault the index in and detect bad pointers.  We only proceed
	 * with the test and sleeping if the non-blocking copy succeeds.
	 *
	 * In the common case the non-blocking copy will succeed and this
	 * will be very fast indeed.
	 */
	for (;;) {
		prepare_to_wait(waitq, &wait, TASK_INTERRUPTIBLE);
		ret = __copy_from_user_inatomic(&kidx, &ring->kernel_head,
						sizeof(u32));
		if (ret) {
			set_task_state(cur, TASK_RUNNING);
			ret = copy_from_user(&kidx, &ring->kernel_head,
					     sizeof(u32));
			if (ret) {
				ret = -EFAULT;
				break;
			}
			continue;
		}

		if (kidx != user_idx)
			break;
		if (signal_pending(cur)) {
			ret = -ERESTARTSYS;
			break;
		}

		schedule();
	}

	finish_wait(waitq, &wait);
out:
	return ret;
}

static int __init syslet_module_init(void)
{
	unsigned long i;

	for (i = 0; i < SYSLET_HASH_NR; i++) {
		init_waitqueue_head(&syslet_waitqs[i]);
		mutex_init(&syslet_muts[i]);
	}

	return 0;
}
module_init(syslet_module_init);
