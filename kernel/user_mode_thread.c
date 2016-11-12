/*
 *  Kernel threads that run user code.
 */

#include <linux/user_mode_thread.h>

/* TODO: fix this crap */
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/mempolicy.h>
#include <linux/sem.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/nsproxy.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/seccomp.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/jiffies.h>
#include <linux/futex.h>
#include <linux/compat.h>
#include <linux/kthread.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/rcupdate.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/freezer.h>
#include <linux/delayacct.h>
#include <linux/taskstats_kern.h>
#include <linux/random.h>
#include <linux/tty.h>
#include <linux/blkdev.h>
#include <linux/fs_struct.h>
#include <linux/magic.h>
#include <linux/perf_event.h>
#include <linux/posix-timers.h>
#include <linux/user-return-notifier.h>
#include <linux/oom.h>
#include <linux/khugepaged.h>
#include <linux/signalfd.h>
#include <linux/uprobes.h>
#include <linux/aio.h>
#include <linux/compiler.h>
#include <linux/sysctl.h>
#include <linux/kcov.h>

static void userthread_entry(void *arg);

struct userthread_internal_info {
	int retval;  /* 0 means successfully started. */
	struct completion started;
	const char *name;

	struct userthread_info *info;
};

int create_user_mode_thread(struct userthread_info *info,
			    const char *name)
{
	pid_t child;
	unsigned int flags;

	struct userthread_internal_info iinfo = {
		.info = info,
		.name = name,
		.retval = 0,
	};

	init_completion(&iinfo.started);

	/*
	 * TODO: we shouldn't fork directly.  Instead we should
	 * fork off of kthreadd, a workqueue, or some similar
	 * clean context, IMO.
	 *
	 * TODO: We actually do want CLONE_VM becuase we should
	 * probably go through the exec() infrastructure to give
	 * us a real context, even though we don't want to run a
	 * real program and we probably don't want a vdso.
	 */
	flags = current->flags;
	current->flags = flags | PF_KTHREAD;
	child = _do_fork(CLONE_UNTRACED,
			 (unsigned long)userthread_entry,
			 (unsigned long)&iinfo, NULL, NULL, 0);
	current->flags = flags;
	if (child < 0)
		return (int)child;

	wait_for_completion(&iinfo.started);
	if (iinfo.retval < 0)
		return iinfo.retval;

	return 0;
}
EXPORT_SYMBOL_GPL(create_user_mode_thread);

static void userthread_entry(void *arg)
{
	struct userthread_internal_info *iinfo = arg;
	struct userthread_info *info = iinfo->info;
	struct cred *cred;

	current->flags &= ~PF_KTHREAD;

	/* TODO: set_task_comm? */
	strncpy(current->comm, iinfo->name, sizeof(current->comm));

	/* Reset signal state */
	spin_lock_irq(&current->sighand->siglock);
	flush_signal_handlers(current, 1);
	spin_unlock_irq(&current->sighand->siglock);

	/* Reset priority */
	set_user_nice(current, 0);

	/* Reset creds */
	cred = prepare_kernel_cred(current);
	if (!cred) {
		iinfo->retval = -ENOMEM;
		goto fail;
	}
	commit_creds(cred);

	iinfo->retval = info->init(info);
	if (iinfo->retval < 0)
		goto fail;

	complete(&iinfo->started);

	/*
	 * We expect main to return so it lands in user mode.  main is
	 * responsible for all cleanup once it starts executing.
	 */
	info->main(info);
	return;

fail:
	complete(&iinfo->started);
	do_exit(0);

}

#ifdef CONFIG_DEBUG_FS

#include <linux/debugfs.h>

struct hello_info {
	struct userthread_info info;
	char buf[32];
};

static int hello_init(struct userthread_info *info)
{
	return 0;
}

static void hello_main(struct userthread_info *info)
{
	struct hello_info *h =
		container_of(info, struct hello_info, info);

	struct hello_info mine = *h;
	kfree(h);

	pr_err("MAIN: %s\n", mine.buf);

	start_thread(current_pt_regs(), 0xbaadc0de, 0xdeadbeef);
	return;  /* segfault! */
}

static ssize_t hello_write(struct file *file,
			   const char __user *user_buf,
			   size_t count, loff_t *ppos)
{
        char buf[32];
	size_t buf_size;
	struct hello_info *h;
	int ret;

	if (count == 0)
		return 0;

        buf_size = min(count, (sizeof(buf)-1));
        if (copy_from_user(buf, user_buf, buf_size))
                return -EFAULT;

        buf[buf_size] = '\0';

	h = kmalloc(sizeof(*h), GFP_KERNEL);
	if (!h) {
		return -ENOMEM;
	}

	h->info.init = hello_init;
	h->info.main = hello_main;
	memcpy(h->buf, buf, sizeof(buf));

	ret = create_user_mode_thread(&h->info, "khelloworld");
	if (ret != 0) {
		kfree(h);
		return ret;
	}

	return count;
}

static const struct file_operations hello_fops = {
	.open = simple_open,
	.write = hello_write,
	.llseek = default_llseek,
};

static int init_test(void)
{
	struct dentry *dir;

	dir = debugfs_create_dir("user_mode_thread_test", NULL);
	if (!dir)
		return -ENOMEM;

	debugfs_create_file("say_hello", 0600, dir, NULL, &hello_fops);
	return 0;
}
device_initcall(init_test);

#endif
