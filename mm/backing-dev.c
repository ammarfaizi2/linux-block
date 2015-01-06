
#include <linux/wait.h>
#include <linux/backing-dev.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/device.h>
#include <trace/events/writeback.h>

static atomic_long_t bdi_seq = ATOMIC_LONG_INIT(0);

struct backing_dev_info default_backing_dev_info = {
	.name		= "default",
	.ra_pages	= VM_MAX_READAHEAD * 1024 / PAGE_CACHE_SIZE,
	.capabilities	= BDI_CAP_MAP_COPY,
};
EXPORT_SYMBOL_GPL(default_backing_dev_info);

struct backing_dev_info noop_backing_dev_info = {
	.name		= "noop",
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK,
};
EXPORT_SYMBOL_GPL(noop_backing_dev_info);

static struct class *bdi_class;

/*
 * bdi_lock protects updates to bdi_list. bdi_list has RCU reader side
 * locking.
 */
DEFINE_SPINLOCK(bdi_lock);
LIST_HEAD(bdi_list);

/* bdi_wq serves all asynchronous writeback tasks */
struct workqueue_struct *bdi_wq;

static void bdi_lock_two(struct bdi_writeback *wb1, struct bdi_writeback *wb2)
{
	if (wb1 < wb2) {
		spin_lock(&wb1->list_lock);
		spin_lock_nested(&wb2->list_lock, 1);
	} else {
		spin_lock(&wb2->list_lock);
		spin_lock_nested(&wb1->list_lock, 1);
	}
}

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/seq_file.h>

static struct dentry *bdi_debug_root;

static void bdi_debug_init(void)
{
	bdi_debug_root = debugfs_create_dir("bdi", NULL);
}

static int bdi_debug_stats_show(struct seq_file *m, void *v)
{
	struct backing_dev_info *bdi = m->private;
	struct bdi_writeback *wb = &bdi->wb;
	unsigned long background_thresh;
	unsigned long dirty_thresh;
	unsigned long bdi_thresh;
	unsigned long nr_dirty, nr_io, nr_more_io;
	struct inode *inode;

	nr_dirty = nr_io = nr_more_io = 0;
	spin_lock(&wb->list_lock);
	list_for_each_entry(inode, &wb->b_dirty, i_wb_link.dirty_list)
		nr_dirty++;
	list_for_each_entry(inode, &wb->b_io, i_wb_link.dirty_list)
		nr_io++;
	list_for_each_entry(inode, &wb->b_more_io, i_wb_link.dirty_list)
		nr_more_io++;
	spin_unlock(&wb->list_lock);

	global_dirty_limits(&background_thresh, &dirty_thresh);
	bdi_thresh = wb_dirty_limit(wb, dirty_thresh);

#define K(x) ((x) << (PAGE_SHIFT - 10))
	seq_printf(m,
		   "BdiWriteback:       %10lu kB\n"
		   "BdiReclaimable:     %10lu kB\n"
		   "BdiDirtyThresh:     %10lu kB\n"
		   "DirtyThresh:        %10lu kB\n"
		   "BackgroundThresh:   %10lu kB\n"
		   "BdiDirtied:         %10lu kB\n"
		   "BdiWritten:         %10lu kB\n"
		   "BdiWriteBandwidth:  %10lu kBps\n"
		   "b_dirty:            %10lu\n"
		   "b_io:               %10lu\n"
		   "b_more_io:          %10lu\n"
		   "bdi_list:           %10u\n"
		   "state:              %10lx\n",
		   (unsigned long) K(wb_stat(wb, WB_WRITEBACK)),
		   (unsigned long) K(wb_stat(wb, WB_RECLAIMABLE)),
		   K(bdi_thresh),
		   K(dirty_thresh),
		   K(background_thresh),
		   (unsigned long) K(wb_stat(wb, WB_DIRTIED)),
		   (unsigned long) K(wb_stat(wb, WB_WRITTEN)),
		   (unsigned long) K(wb->write_bandwidth),
		   nr_dirty,
		   nr_io,
		   nr_more_io,
		   !list_empty(&bdi->bdi_list), bdi->wb.state);
#undef K

	return 0;
}

static int bdi_debug_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, bdi_debug_stats_show, inode->i_private);
}

static const struct file_operations bdi_debug_stats_fops = {
	.open		= bdi_debug_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void bdi_debug_register(struct backing_dev_info *bdi, const char *name)
{
	bdi->debug_dir = debugfs_create_dir(name, bdi_debug_root);
	bdi->debug_stats = debugfs_create_file("stats", 0444, bdi->debug_dir,
					       bdi, &bdi_debug_stats_fops);
}

static void bdi_debug_unregister(struct backing_dev_info *bdi)
{
	debugfs_remove(bdi->debug_stats);
	debugfs_remove(bdi->debug_dir);
}
#else
static inline void bdi_debug_init(void)
{
}
static inline void bdi_debug_register(struct backing_dev_info *bdi,
				      const char *name)
{
}
static inline void bdi_debug_unregister(struct backing_dev_info *bdi)
{
}
#endif

static ssize_t read_ahead_kb_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);
	unsigned long read_ahead_kb;
	ssize_t ret;

	ret = kstrtoul(buf, 10, &read_ahead_kb);
	if (ret < 0)
		return ret;

	bdi->ra_pages = read_ahead_kb >> (PAGE_SHIFT - 10);

	return count;
}

#define K(pages) ((pages) << (PAGE_SHIFT - 10))

#define BDI_SHOW(name, expr)						\
static ssize_t name##_show(struct device *dev,				\
			   struct device_attribute *attr, char *page)	\
{									\
	struct backing_dev_info *bdi = dev_get_drvdata(dev);		\
									\
	return snprintf(page, PAGE_SIZE-1, "%lld\n", (long long)expr);	\
}									\
static DEVICE_ATTR_RW(name);

BDI_SHOW(read_ahead_kb, K(bdi->ra_pages))

static ssize_t min_ratio_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);
	unsigned int ratio;
	ssize_t ret;

	ret = kstrtouint(buf, 10, &ratio);
	if (ret < 0)
		return ret;

	ret = bdi_set_min_ratio(bdi, ratio);
	if (!ret)
		ret = count;

	return ret;
}
BDI_SHOW(min_ratio, bdi->min_ratio)

static ssize_t max_ratio_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);
	unsigned int ratio;
	ssize_t ret;

	ret = kstrtouint(buf, 10, &ratio);
	if (ret < 0)
		return ret;

	ret = bdi_set_max_ratio(bdi, ratio);
	if (!ret)
		ret = count;

	return ret;
}
BDI_SHOW(max_ratio, bdi->max_ratio)

static ssize_t stable_pages_required_show(struct device *dev,
					  struct device_attribute *attr,
					  char *page)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);

	return snprintf(page, PAGE_SIZE-1, "%d\n",
			bdi_cap_stable_pages_required(bdi) ? 1 : 0);
}
static DEVICE_ATTR_RO(stable_pages_required);

static ssize_t strictlimit_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);
	unsigned int val;
	ssize_t ret;

	ret = kstrtouint(buf, 10, &val);
	if (ret < 0)
		return ret;

	switch (val) {
	case 0:
		bdi->capabilities &= ~BDI_CAP_STRICTLIMIT;
		break;
	case 1:
		bdi->capabilities |= BDI_CAP_STRICTLIMIT;
		break;
	default:
		return -EINVAL;
	}

	return count;
}
static ssize_t strictlimit_show(struct device *dev,
		struct device_attribute *attr, char *page)
{
	struct backing_dev_info *bdi = dev_get_drvdata(dev);

	return snprintf(page, PAGE_SIZE-1, "%d\n",
			!!(bdi->capabilities & BDI_CAP_STRICTLIMIT));
}
static DEVICE_ATTR_RW(strictlimit);

static struct attribute *bdi_dev_attrs[] = {
	&dev_attr_read_ahead_kb.attr,
	&dev_attr_min_ratio.attr,
	&dev_attr_max_ratio.attr,
	&dev_attr_stable_pages_required.attr,
	&dev_attr_strictlimit.attr,
	NULL,
};
ATTRIBUTE_GROUPS(bdi_dev);

static __init int bdi_class_init(void)
{
	bdi_class = class_create(THIS_MODULE, "bdi");
	if (IS_ERR(bdi_class))
		return PTR_ERR(bdi_class);

	bdi_class->dev_groups = bdi_dev_groups;
	bdi_debug_init();
	return 0;
}
postcore_initcall(bdi_class_init);

static int __init default_bdi_init(void)
{
	int err;

	bdi_wq = alloc_workqueue("writeback", WQ_MEM_RECLAIM | WQ_FREEZABLE |
					      WQ_UNBOUND | WQ_SYSFS, 0);
	if (!bdi_wq)
		return -ENOMEM;

	err = bdi_init(&default_backing_dev_info);
	if (!err)
		bdi_register(&default_backing_dev_info, NULL, "default");
	err = bdi_init(&noop_backing_dev_info);

	return err;
}
subsys_initcall(default_bdi_init);

/*
 * This function is used when the first inode for this wb is marked dirty. It
 * wakes-up the corresponding bdi thread which should then take care of the
 * periodic background write-out of dirty inodes. Since the write-out would
 * starts only 'dirty_writeback_interval' centisecs from now anyway, we just
 * set up a timer which wakes the bdi thread up later.
 *
 * Note, we wouldn't bother setting up the timer, but this function is on the
 * fast-path (used by '__mark_inode_dirty()'), so we save few context switches
 * by delaying the wake-up.
 *
 * We have to be careful not to postpone flush work if it is scheduled for
 * earlier. Thus we use queue_delayed_work().
 */
void wb_wakeup_delayed(struct bdi_writeback *wb)
{
	unsigned long timeout;

	timeout = msecs_to_jiffies(dirty_writeback_interval * 10);
	spin_lock_bh(&wb->work_lock);
	if (test_bit(WB_registered, &wb->state))
		queue_delayed_work(bdi_wq, &wb->dwork, timeout);
	spin_unlock_bh(&wb->work_lock);
}

/*
 * Initial write bandwidth: 100 MB/s
 */
#define INIT_BW		(100 << (20 - PAGE_SHIFT))

static int wb_init(struct bdi_writeback *wb, struct backing_dev_info *bdi,
		   gfp_t gfp)
{
	int i, err;

	memset(wb, 0, sizeof(*wb));

	wb->bdi = bdi;
	wb->last_old_flush = jiffies;
	INIT_LIST_HEAD(&wb->b_dirty);
	INIT_LIST_HEAD(&wb->b_io);
	INIT_LIST_HEAD(&wb->b_more_io);
	spin_lock_init(&wb->list_lock);

	wb->bw_time_stamp = jiffies;
	wb->balanced_dirty_ratelimit = INIT_BW;
	wb->dirty_ratelimit = INIT_BW;
	wb->write_bandwidth = INIT_BW;
	wb->avg_write_bandwidth = INIT_BW;

	spin_lock_init(&wb->work_lock);
	INIT_LIST_HEAD(&wb->work_list);
	INIT_DELAYED_WORK(&wb->dwork, wb_workfn);

	err = fprop_local_init_percpu(&wb->completions, gfp);
	if (err)
		return err;

	for (i = 0; i < NR_WB_STAT_ITEMS; i++) {
		err = percpu_counter_init(&wb->stat[i], 0, gfp);
		if (err) {
			while (--i)
				percpu_counter_destroy(&wb->stat[i]);
			fprop_local_destroy_percpu(&wb->completions);
			return err;
		}
	}

	return 0;
}

/*
 * Remove bdi from the global list and shutdown any threads we have running
 */
static void wb_shutdown(struct bdi_writeback *wb)
{
	/* Make sure nobody queues further work */
	spin_lock_bh(&wb->work_lock);
	clear_bit(WB_registered, &wb->state);
	spin_unlock_bh(&wb->work_lock);

	/*
	 * Drain work list and shutdown the delayed_work.  !WB_registered
	 * tells wb_workfn() that @wb is dying and its work_list needs to
	 * be drained no matter what.
	 */
	mod_delayed_work(bdi_wq, &wb->dwork, 0);
	flush_delayed_work(&wb->dwork);
	WARN_ON(!list_empty(&wb->work_list));
	WARN_ON(delayed_work_pending(&wb->dwork));
}

static void wb_exit(struct bdi_writeback *wb)
{
	int i;

	WARN_ON(delayed_work_pending(&wb->dwork));

	/*
	 * Splice our entries to the default_backing_dev_info.  This
	 * condition shouldn't happen.  @wb must be empty at this point and
	 * dirty inodes on it might cause other issues.  This workaround is
	 * added by ce5f8e779519 ("writeback: splice dirty inode entries to
	 * default bdi on bdi_destroy()") without root-causing the issue.
	 *
	 * http://lkml.kernel.org/g/1253038617-30204-11-git-send-email-jens.axboe@oracle.com
	 * http://thread.gmane.org/gmane.linux.file-systems/35341/focus=35350
	 *
	 * We should probably add WARN_ON() to find out whether it still
	 * happens and track it down if so.
	 */
	if (wb_has_dirty_io(wb)) {
		struct bdi_writeback *dst = &default_backing_dev_info.wb;

		bdi_lock_two(wb, dst);
		list_splice(&wb->b_dirty, &dst->b_dirty);
		list_splice(&wb->b_io, &dst->b_io);
		list_splice(&wb->b_more_io, &dst->b_more_io);
		spin_unlock(&wb->list_lock);
		spin_unlock(&dst->list_lock);
	}

	for (i = 0; i < NR_WB_STAT_ITEMS; i++)
		percpu_counter_destroy(&wb->stat[i]);

	fprop_local_destroy_percpu(&wb->completions);
}

#ifdef CONFIG_CGROUP_WRITEBACK

/*
 * cgwb_lock protects bdi->cgwb_tree and blkcg->cgwb_list where the former
 * is also RCU protected.  cgwb_shutdown_mutex synchronizes shutdown
 * attempts from bdi and blkcg destructions.  For details, see
 * cgwb_shutdown_prepare/commit().
 */
static DEFINE_SPINLOCK(cgwb_lock);
static DEFINE_MUTEX(cgwb_shutdown_mutex);

int __cgwb_create(struct backing_dev_info *bdi,
		  struct cgroup_subsys_state *blkcg_css)
{
	struct blkcg *blkcg = css_to_blkcg(blkcg_css);
	struct bdi_writeback *wb;
	unsigned long flags;
	int ret;

	wb = kzalloc(sizeof(*wb), GFP_ATOMIC);
	if (!wb)
		return -ENOMEM;

	ret = wb_init(wb, bdi, GFP_ATOMIC);
	if (ret) {
		kfree(wb);
		return -ENOMEM;
	}

	wb->blkcg_css = blkcg_css;
	set_bit(WB_registered, &wb->state); /* cgwbs are always registered */

	ret = -ENODEV;
	spin_lock_irqsave(&cgwb_lock, flags);
	/* the root wb determines the registered state of the whole bdi */
	if (test_bit(WB_registered, &bdi->wb.state)) {
		/* we might have raced w/ another instance of this function */
		ret = radix_tree_insert(&bdi->cgwb_tree, blkcg_css->id, wb);
		if (!ret)
			list_add_tail(&wb->blkcg_node, &blkcg->cgwb_list);
	}
	spin_unlock_irqrestore(&cgwb_lock, flags);
	if (ret) {
		wb_exit(wb);
		if (ret != -EEXIST)
			return ret;
	}
	return 0;
}

/**
 * cgwb_shutdown_prepare - prepare to shutdown a cgwb
 * @wb: cgwb to be shutdown
 * @to_shutdown: list to queue @wb on
 *
 * This function is called to queue @wb for shutdown on @to_shutdown.  The
 * bdi_writeback indexes use the cgwb_lock spinlock but wb_shutdown() needs
 * process context, so this function can be called while holding cgwb_lock
 * and cgwb_shutdown_mutex to queue cgwbs for shutdown.  Once all target
 * cgwbs are queued, the caller should release cgwb_lock and invoke
 * cgwb_shutdown_commit().
 */
static void cgwb_shutdown_prepare(struct bdi_writeback *wb,
				  struct list_head *to_shutdown)
{
	lockdep_assert_held(&cgwb_lock);
	lockdep_assert_held(&cgwb_shutdown_mutex);

	WARN_ON(!test_bit(WB_registered, &wb->state));
	clear_bit(WB_registered, &wb->state);
	list_add_tail(&wb->shutdown_node, to_shutdown);
}

/**
 * cgwb_shutdown_commit - commit cgwb shutdowns
 * @to_shutdown: list of cgwbs to shutdown
 *
 * This function is called after @to_shutdown is built by calls to
 * cgwb_shutdown_prepare() and cgwb_lock is released.  It invokes
 * wb_shutdown() on all cgwbs on the list.  bdi and blkcg may try to
 * shutdown the same cgwbs and should wait till completion if shutdown is
 * initiated by the other.  This synchronization is achieved through
 * cgwb_shutdown_mutex which should have been acquired before the
 * cgwb_shutdown_prepare() invocations.
 */
static void cgwb_shutdown_commit(struct list_head *to_shutdown)
{
	struct bdi_writeback *wb;

	lockdep_assert_held(&cgwb_shutdown_mutex);

	list_for_each_entry(wb, to_shutdown, shutdown_node)
		wb_shutdown(wb);
}

static void cgwb_exit(struct bdi_writeback *wb)
{
	WARN_ON(!radix_tree_delete(&wb->bdi->cgwb_tree, wb->blkcg_css->id));
	list_del(&wb->blkcg_node);
	wb_exit(wb);
	kfree_rcu(wb, rcu);
}

static void cgwb_bdi_init(struct backing_dev_info *bdi)
{
	bdi->wb.blkcg_css = blkcg_root_css;
	INIT_RADIX_TREE(&bdi->cgwb_tree, GFP_ATOMIC);
}

/**
 * cgwb_bdi_shutdown - @bdi is being shut down, shut down all cgwbs
 * @bdi: bdi being shut down
 */
static void cgwb_bdi_shutdown(struct backing_dev_info *bdi)
{
	LIST_HEAD(to_shutdown);
	struct radix_tree_iter iter;
	void **slot;

	WARN_ON(test_bit(WB_registered, &bdi->wb.state));

	mutex_lock(&cgwb_shutdown_mutex);
	spin_lock_irq(&cgwb_lock);

	radix_tree_for_each_slot(slot, &bdi->cgwb_tree, &iter, 0)
		cgwb_shutdown_prepare(*slot, &to_shutdown);

	spin_unlock_irq(&cgwb_lock);
	cgwb_shutdown_commit(&to_shutdown);
	mutex_unlock(&cgwb_shutdown_mutex);
}

/**
 * cgwb_bdi_exit - @bdi is being exit, exit all its cgwbs
 * @bdi: bdi being shut down
 */
static void cgwb_bdi_exit(struct backing_dev_info *bdi)
{
	LIST_HEAD(to_free);
	struct radix_tree_iter iter;
	void **slot;

	spin_lock_irq(&cgwb_lock);
	radix_tree_for_each_slot(slot, &bdi->cgwb_tree, &iter, 0) {
		struct bdi_writeback *wb = *slot;

		WARN_ON(test_bit(WB_registered, &wb->state));
		cgwb_exit(wb);
	}
	spin_unlock_irq(&cgwb_lock);
}

/**
 * cgwb_blkcg_released - a blkcg is being destroyed, release all matching cgwbs
 * @blkcg_css: blkcg being destroyed
 */
void cgwb_blkcg_released(struct cgroup_subsys_state *blkcg_css)
{
	LIST_HEAD(to_shutdown);
	struct blkcg *blkcg = css_to_blkcg(blkcg_css);
	struct bdi_writeback *wb, *next;

	mutex_lock(&cgwb_shutdown_mutex);
	spin_lock_irq(&cgwb_lock);

	list_for_each_entry_safe(wb, next, &blkcg->cgwb_list, blkcg_node)
		cgwb_shutdown_prepare(wb, &to_shutdown);

	spin_unlock_irq(&cgwb_lock);
	cgwb_shutdown_commit(&to_shutdown);
	mutex_unlock(&cgwb_shutdown_mutex);

	spin_lock_irq(&cgwb_lock);
	list_for_each_entry_safe(wb, next, &blkcg->cgwb_list, blkcg_node)
		cgwb_exit(wb);
	spin_unlock_irq(&cgwb_lock);
}

#else	/* CONFIG_CGROUP_WRITEBACK */

static void cgwb_bdi_init(struct backing_dev_info *bdi) { }
static void cgwb_bdi_shutdown(struct backing_dev_info *bdi) { }
static void cgwb_bdi_exit(struct backing_dev_info *bdi) { }

#endif	/* CONFIG_CGROUP_WRITEBACK */

int bdi_init(struct backing_dev_info *bdi)
{
	int err;

	bdi->dev = NULL;

	bdi->min_ratio = 0;
	bdi->max_ratio = 100;
	bdi->max_prop_frac = FPROP_FRAC_BASE;
	INIT_LIST_HEAD(&bdi->bdi_list);
	init_waitqueue_head(&bdi->wb_waitq);

	err = wb_init(&bdi->wb, bdi, GFP_KERNEL);
	if (err)
		return err;

	cgwb_bdi_init(bdi);
	return 0;
}
EXPORT_SYMBOL(bdi_init);

int bdi_register(struct backing_dev_info *bdi, struct device *parent,
		const char *fmt, ...)
{
	va_list args;
	struct device *dev;

	if (bdi->dev)	/* The driver needs to use separate queues per device */
		return 0;

	va_start(args, fmt);
	dev = device_create_vargs(bdi_class, parent, MKDEV(0, 0), bdi, fmt, args);
	va_end(args);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	bdi->dev = dev;

	bdi_debug_register(bdi, dev_name(dev));
	set_bit(WB_registered, &bdi->wb.state);

	spin_lock_bh(&bdi_lock);
	list_add_tail_rcu(&bdi->bdi_list, &bdi_list);
	spin_unlock_bh(&bdi_lock);

	trace_writeback_bdi_register(bdi);
	return 0;
}
EXPORT_SYMBOL(bdi_register);

int bdi_register_dev(struct backing_dev_info *bdi, dev_t dev)
{
	return bdi_register(bdi, NULL, "%u:%u", MAJOR(dev), MINOR(dev));
}
EXPORT_SYMBOL(bdi_register_dev);

/*
 * This bdi is going away now, make sure that no super_blocks point to it
 */
static void bdi_prune_sb(struct backing_dev_info *bdi)
{
	struct super_block *sb;

	spin_lock(&sb_lock);
	list_for_each_entry(sb, &super_blocks, s_list) {
		if (sb->s_bdi == bdi)
			sb->s_bdi = &default_backing_dev_info;
	}
	spin_unlock(&sb_lock);
}

/*
 * Remove bdi from bdi_list, and ensure that it is no longer visible
 */
static void bdi_remove_from_list(struct backing_dev_info *bdi)
{
	spin_lock_bh(&bdi_lock);
	list_del_rcu(&bdi->bdi_list);
	spin_unlock_bh(&bdi_lock);

	synchronize_rcu_expedited();
}

void bdi_unregister(struct backing_dev_info *bdi)
{
	if (bdi->dev) {
		bdi_set_min_ratio(bdi, 0);
		trace_writeback_bdi_unregister(bdi);
		bdi_prune_sb(bdi);

		if (bdi_cap_writeback_dirty(bdi)) {
			/* make sure nobody finds us on the bdi_list anymore */
			bdi_remove_from_list(bdi);
			wb_shutdown(&bdi->wb);
			cgwb_bdi_shutdown(bdi);
		}

		bdi_debug_unregister(bdi);
		device_unregister(bdi->dev);
		bdi->dev = NULL;
	}
}
EXPORT_SYMBOL(bdi_unregister);

void bdi_destroy(struct backing_dev_info *bdi)
{
	bdi_unregister(bdi);
	cgwb_bdi_exit(bdi);
	wb_exit(&bdi->wb);
}
EXPORT_SYMBOL(bdi_destroy);

/*
 * For use from filesystems to quickly init and register a bdi associated
 * with dirty writeback
 */
int bdi_setup_and_register(struct backing_dev_info *bdi, char *name,
			   unsigned int cap)
{
	int err;

	bdi->name = name;
	bdi->capabilities = cap;
	err = bdi_init(bdi);
	if (err)
		return err;

	err = bdi_register(bdi, NULL, "%.28s-%ld", name,
			   atomic_long_inc_return(&bdi_seq));
	if (err) {
		bdi_destroy(bdi);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(bdi_setup_and_register);

static wait_queue_head_t congestion_wqh[2] = {
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[0]),
		__WAIT_QUEUE_HEAD_INITIALIZER(congestion_wqh[1])
	};
static atomic_t nr_wb_congested[2];

void clear_wb_congested(struct bdi_writeback *wb, int sync)
{
	wait_queue_head_t *wqh = &congestion_wqh[sync];
	enum wb_state bit;

	bit = sync ? WB_sync_congested : WB_async_congested;
	if (test_and_clear_bit(bit, &wb->state))
		atomic_dec(&nr_wb_congested[sync]);
	smp_mb__after_atomic();
	if (waitqueue_active(wqh))
		wake_up(wqh);
}
EXPORT_SYMBOL(clear_wb_congested);

void set_wb_congested(struct bdi_writeback *wb, int sync)
{
	enum wb_state bit;

	bit = sync ? WB_sync_congested : WB_async_congested;
	if (!test_and_set_bit(bit, &wb->state))
		atomic_inc(&nr_wb_congested[sync]);
}
EXPORT_SYMBOL(set_wb_congested);

/**
 * congestion_wait - wait for a backing_dev to become uncongested
 * @sync: SYNC or ASYNC IO
 * @timeout: timeout in jiffies
 *
 * Waits for up to @timeout jiffies for a backing_dev (any backing_dev) to exit
 * write congestion.  If no backing_devs are congested then just wait for the
 * next write to be completed.
 */
long congestion_wait(int sync, long timeout)
{
	long ret;
	unsigned long start = jiffies;
	DEFINE_WAIT(wait);
	wait_queue_head_t *wqh = &congestion_wqh[sync];

	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	ret = io_schedule_timeout(timeout);
	finish_wait(wqh, &wait);

	trace_writeback_congestion_wait(jiffies_to_usecs(timeout),
					jiffies_to_usecs(jiffies - start));

	return ret;
}
EXPORT_SYMBOL(congestion_wait);

/**
 * wait_iff_congested - Conditionally wait for a backing_dev to become uncongested or a zone to complete writes
 * @zone: A zone to check if it is heavily congested
 * @sync: SYNC or ASYNC IO
 * @timeout: timeout in jiffies
 *
 * In the event of a congested backing_dev (any backing_dev) and the given
 * @zone has experienced recent congestion, this waits for up to @timeout
 * jiffies for either a BDI to exit congestion of the given @sync queue
 * or a write to complete.
 *
 * In the absence of zone congestion, cond_resched() is called to yield
 * the processor if necessary but otherwise does not sleep.
 *
 * The return value is 0 if the sleep is for the full timeout. Otherwise,
 * it is the number of jiffies that were still remaining when the function
 * returned. return_value == timeout implies the function did not sleep.
 */
long wait_iff_congested(struct zone *zone, int sync, long timeout)
{
	long ret;
	unsigned long start = jiffies;
	DEFINE_WAIT(wait);
	wait_queue_head_t *wqh = &congestion_wqh[sync];

	/*
	 * If there is no congestion, or heavy congestion is not being
	 * encountered in the current zone, yield if necessary instead
	 * of sleeping on the congestion queue
	 */
	if (atomic_read(&nr_wb_congested[sync]) == 0 ||
	    !test_bit(ZONE_CONGESTED, &zone->flags)) {
		cond_resched();

		/* In case we scheduled, work out time remaining */
		ret = timeout - (jiffies - start);
		if (ret < 0)
			ret = 0;

		goto out;
	}

	/* Sleep until uncongested or a write happens */
	prepare_to_wait(wqh, &wait, TASK_UNINTERRUPTIBLE);
	ret = io_schedule_timeout(timeout);
	finish_wait(wqh, &wait);

out:
	trace_writeback_wait_iff_congested(jiffies_to_usecs(timeout),
					jiffies_to_usecs(jiffies - start));

	return ret;
}
EXPORT_SYMBOL(wait_iff_congested);

int pdflush_proc_obsolete(struct ctl_table *table, int write,
			void __user *buffer, size_t *lenp, loff_t *ppos)
{
	char kbuf[] = "0\n";

	if (*ppos || *lenp < sizeof(kbuf)) {
		*lenp = 0;
		return 0;
	}

	if (copy_to_user(buffer, kbuf, sizeof(kbuf)))
		return -EFAULT;
	printk_once(KERN_WARNING "%s exported in /proc is scheduled for removal\n",
			table->procname);

	*lenp = 2;
	*ppos += *lenp;
	return 2;
}
