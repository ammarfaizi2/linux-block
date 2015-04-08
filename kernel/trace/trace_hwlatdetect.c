/*
 * trace_hwlatdetect.c - A simple Hardware Latency detector.
 *
 * Use this tracer to detect large system latencies induced by the behavior of
 * certain underlying system hardware or firmware, independent of Linux itself.
 * The code was developed originally to detect the presence of SMIs on Intel
 * and AMD systems, although there is no dependency upon x86 herein.
 *
 * The classical example usage of this tracer is in detecting the presence of
 * SMIs or System Management Interrupts on Intel and AMD systems. An SMI is a
 * somewhat special form of hardware interrupt spawned from earlier CPU debug
 * modes in which the (BIOS/EFI/etc.) firmware arranges for the South Bridge
 * LPC (or other device) to generate a special interrupt under certain
 * circumstances, for example, upon expiration of a special SMI timer device,
 * due to certain external thermal readings, on certain I/O address accesses,
 * and other situations. An SMI hits a special CPU pin, triggers a special
 * SMI mode (complete with special memory map), and the OS is unaware.
 *
 * Although certain hardware-inducing latencies are necessary (for example,
 * a modern system often requires an SMI handler for correct thermal control
 * and remote management) they can wreak havoc upon any OS-level performance
 * guarantees toward low-latency, especially when the OS is not even made
 * aware of the presence of these interrupts. For this reason, we need a
 * somewhat brute force mechanism to detect these interrupts. In this case,
 * we do it by hogging all of the CPU(s) for configurable timer intervals,
 * sampling the built-in CPU timer, looking for discontiguous readings.
 *
 * WARNING: This implementation necessarily introduces latencies. Therefore,
 *          you should NEVER use this tracer while running in a production
 *          environment requiring any kind of low-latency performance
 *          guarantee(s).
 *
 * Copyright (C) 2008-2009 Jon Masters, Red Hat, Inc. <jcm@redhat.com>
 * Copyright (C) 2013-2015 Steven Rostedt, Red Hat, Inc. <srostedt@redhat.com>
 *
 * Includes useful feedback from Clark Williams <clark@redhat.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/trace_clock.h>
#include <linux/ring_buffer.h>
#include <linux/seq_file.h>
#include <linux/kthread.h>
#include <linux/hrtimer.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/slab.h>

#include "trace.h"

#define U64STR_SIZE		22			/* 20 digits max */

#define BANNER			"hwlat_detector: "
#define DEFAULT_SAMPLE_WINDOW	1000000			/* 1s */
#define DEFAULT_SAMPLE_WIDTH	500000			/* 0.5s */
#define DEFAULT_LAT_THRESHOLD	10			/* 10us */

/* Tracer handle */

static struct trace_array *hwlat_detector_trace_array;

static struct task_struct *kthread;		/* sampling thread */

/* DebugFS filesystem entries */

static struct dentry *debug_count;		/* total detect count */
static struct dentry *debug_sample_width;	/* sample width us */
static struct dentry *debug_sample_window;	/* sample window us */

/* Save the previous tracing_thresh value */
static unsigned long save_tracing_thresh;

/* Individual samples and global state */

/* If the user changed threshold, remember it */
static u64 last_tracing_thresh = DEFAULT_LAT_THRESHOLD * NSEC_PER_USEC;

/*
 * Individual latency samples are stored here when detected and packed into
 * the ring_buffer circular buffer, where they are overwritten when
 * more than buf_size/sizeof(sample) samples are received.
 */
struct sample {
	u64		seqnum;		/* unique sequence */
	u64		duration;	/* ktime delta */
	u64		outer_duration;	/* ktime delta (outer loop) */
	struct timespec	timestamp;	/* wall time */
};

/* keep the global state somewhere. */
static struct data {

	struct mutex lock;		/* protect changes */

	u64	count;			/* total since reset */

	u64	sample_window;		/* total sampling window (on+off) */
	u64	sample_width;		/* active sampling portion of window */

} data = {
	.sample_window		= DEFAULT_SAMPLE_WINDOW,
	.sample_width		= DEFAULT_SAMPLE_WIDTH,
};

static void trace_hwlat_sample(struct sample *sample)
{
	struct trace_array *tr = hwlat_detector_trace_array;
	struct ftrace_event_call *call = &event_hwlat_detector;
	struct ring_buffer *buffer = tr->trace_buffer.buffer;
	struct ring_buffer_event *event;
	struct trace_hwlat_detector *entry;
	unsigned long flags;
	int pc;

	pc = preempt_count();
	local_save_flags(flags);

	event = trace_buffer_lock_reserve(buffer, TRACE_HWLAT, sizeof(*entry),
					  flags, pc);
	if (!event)
		return;
	entry	= ring_buffer_event_data(event);
	entry->seqnum			= sample->seqnum;
	entry->duration			= sample->duration;
	entry->outer_duration		= sample->outer_duration;
	entry->timestamp		= sample->timestamp;

	if (!call_filter_check_discard(call, entry, buffer, event))
		__buffer_unlock_commit(buffer, event);
}

/* Macros used in case the time capture is changed */
#define time_type	u64
#define time_get()	trace_clock_local()
#define time_to_us(x)	div_u64(x, 1000)
#define time_sub(a, b)	((a) - (b))
#define init_time(a, b)	(a = b)
#define time_u64(a)	a

/**
 * get_sample - sample the CPU TSC and look for likely hardware latencies
 *
 * Used to repeatedly capture the CPU TSC (or similar), looking for potential
 * hardware-induced latency. Called with interrupts disabled and with
 * data.lock held.
 */
static int get_sample(void)
{
	struct trace_array *tr = hwlat_detector_trace_array;
	time_type start, t1, t2, last_t2;
	s64 diff, total = 0, last_total = 0;
	u64 sample = 0;
	u64 thresh = tracing_thresh;
	u64 outer_sample = 0;
	int ret = -1;

	do_div(thresh, NSEC_PER_USEC); /* modifies interval value */

	init_time(last_t2, 0);
	start = time_get(); /* start timestamp */

	do {

		t1 = time_get();	/* we'll look for a discontinuity */
		t2 = time_get();

		if (time_u64(last_t2)) {
			/* Check the delta from outer loop (t2 to next t1) */
			diff = time_to_us(time_sub(t1, last_t2));
			/* This shouldn't happen */
			if (diff < 0) {
				pr_err(BANNER "time running backwards\n");
				goto out;
			}
			if (diff > outer_sample)
				outer_sample = diff;
		}
		last_t2 = t2;

		total = time_to_us(time_sub(t2, start)); /* sample width */

		/* Check for possible overflows */
		if (total < last_total) {
			pr_err("Time total overflowed\n");
			break;
		}
		last_total = total;

		/* This checks the inner loop (t1 to t2) */
		diff = time_to_us(time_sub(t2, t1));     /* current diff */

		/* This shouldn't happen */
		if (diff < 0) {
			pr_err(BANNER "time running backwards\n");
			goto out;
		}

		if (diff > sample)
			sample = diff; /* only want highest value */

	} while (total <= data.sample_width);

	ret = 0;

	/* If we exceed the threshold value, we have found a hardware latency */
	if (sample > thresh || outer_sample > thresh) {
		struct sample s;

		ret = 1;

		data.count++;
		s.seqnum = data.count;
		s.duration = sample;
		s.outer_duration = outer_sample;
		s.timestamp = CURRENT_TIME;
		trace_hwlat_sample(&s);

		/* Keep a running maximum ever recorded hardware latency */
		if (sample > tr->max_latency)
			tr->max_latency = sample;
	}

out:
	return ret;
}

/*
 * kthread_fn - The CPU time sampling/hardware latency detection kernel thread
 *
 * Used to periodically sample the CPU TSC via a call to get_sample. We
 * disable interrupts, which does (intentionally) introduce latency since we
 * need to ensure nothing else might be running (and thus preempting).
 * Obviously this should never be used in production environments.
 *
 * Currently this runs on which ever CPU it was scheduled on, but most
 * real-world hardware latency situations occur across several CPUs,
 * but we might later generalize this if we find there are any actualy
 * systems with alternate SMI delivery or other hardware latencies.
 */
static int kthread_fn(void *unused)
{
	int ret;
	u64 interval;

	while (!kthread_should_stop()) {

		local_irq_disable();
		ret = get_sample();
		local_irq_enable();

		mutex_lock(&data.lock);
		interval = data.sample_window - data.sample_width;
		mutex_unlock(&data.lock);

		do_div(interval, USEC_PER_MSEC); /* modifies interval value */

		if (msleep_interruptible(interval))
			break;
	}

	return 0;
}

/**
 * start_kthread - Kick off the hardware latency sampling/detector kthread
 *
 * This starts a kernel thread that will sit and sample the CPU timestamp
 * counter (TSC or similar) and look for potential hardware latencies.
 */
static int start_kthread(void)
{
	kthread = kthread_run(kthread_fn, NULL, "hwlat_detector");
	if (IS_ERR(kthread)) {
		kthread = NULL;
		pr_err(BANNER "could not start sampling thread\n");
		return -ENOMEM;
	}

	return 0;
}

/**
 * stop_kthread - Inform the hardware latency samping/detector kthread to stop
 *
 * This kicks the running hardware latency sampling/detector kernel thread and
 * tells it to stop sampling now. Use this on unload and at system shutdown.
 */
static int stop_kthread(void)
{
	int ret = 0;

	if (kthread) {
		ret = kthread_stop(kthread);
		kthread = NULL;
	}

	return ret;
}

/**
 * __reset_stats - Reset statistics for the hardware latency detector
 *
 * We use data to store various statistics and global state. We call this
 * function in order to reset those when "enable" is toggled on or off, and
 * also at initialization.
 */
static void __reset_stats(struct trace_array *tr)
{
	data.count = 0;
	tr->max_latency = 0;
}

/**
 * init_stats - Setup global state statistics for the hardware latency detector
 *
 * We use data to store various statistics and global state.
 */
static void init_stats(struct trace_array *tr)
{
	__reset_stats(tr);

	save_tracing_thresh = tracing_thresh;

	/* tracing_thresh is in nsecs, we speak in usecs */
	if (!tracing_thresh)
		tracing_thresh = last_tracing_thresh;
}

/*
 * hwlat_read - Wrapper read function for global state debugfs entries
 * @filp: The active open file structure for the debugfs "file"
 * @ubuf: The userspace provided buffer to read value into
 * @cnt: The maximum number of bytes to read
 * @ppos: The current "file" position
 *
 * This function provides a generic read implementation for the global state
 * "data" structure debugfs filesystem entries.
 */
static ssize_t hwlat_read(struct file *filp, char __user *ubuf,
			  size_t cnt, loff_t *ppos)
{
	unsigned long *entry = filp->private_data;
	char buf[U64STR_SIZE];
	unsigned long val = 0;
	int len = 0;

	memset(buf, 0, sizeof(buf));

	if (!entry)
		return -EFAULT;

	val = *entry;

	len = snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)val);

	return simple_read_from_buffer(ubuf, cnt, ppos, buf, len);

}

/*
 * hwlat_write - Wrapper write function for global state debugfs entries
 * @filp: The active open file structure for the debugfs "file"
 * @ubuf: The userspace provided buffer to write value from
 * @cnt: The maximum number of bytes to write
 * @ppos: The current "file" position
 *
 * This function provides a generic write implementation for the global state
 * "data" structure debugfs filesystem entries.
 */
static ssize_t hwlat_write(struct file *filp, const char __user *ubuf,
			   size_t cnt, loff_t *ppos)
{
	unsigned long *entry = filp->private_data;
	char buf[U64STR_SIZE];
	int csize = min(cnt, sizeof(buf)-1);
	u64 val = 0;
	int err = 0;

	if (copy_from_user(buf, ubuf, csize))
		return -EFAULT;
	buf[csize] = '\0';
	err = kstrtoull(buf, 10, &val);
	if (err)
		return -EINVAL;

	*entry = val;

	return csize;
}

/**
 * debug_width_write - Write function for "width" debugfs entry
 * @filp: The active open file structure for the debugfs "file"
 * @ubuf: The user buffer that contains the value to write
 * @cnt: The maximum number of bytes to write to "file"
 * @ppos: The current position in the debugfs "file"
 *
 * This function provides a write implementation for the "width" debugfs
 * interface to the hardware latency detector. It can be used to configure
 * for how many us of the total window us we will actively sample for any
 * hardware-induced latency periods. Obviously, it is not possible to
 * sample constantly and have the system respond to a sample reader, or,
 * worse, without having the system appear to have gone out to lunch. It
 * is enforced that width is less that the total window size.
 */
static ssize_t
debug_width_write(struct file *filp, const char __user *ubuf,
		  size_t cnt, loff_t *ppos)
{
	char buf[U64STR_SIZE];
	int csize = min(cnt, sizeof(buf));
	u64 val = 0;
	int err = 0;

	memset(buf, '\0', sizeof(buf));
	if (copy_from_user(buf, ubuf, csize))
		return -EFAULT;

	buf[U64STR_SIZE-1] = '\0';			/* just in case */
	err = kstrtoull(buf, 10, &val);
	if (0 != err)
		return -EINVAL;

	mutex_lock(&data.lock);
	if (val < data.sample_window)
		data.sample_width = val;
	else
		csize = -EINVAL;
	mutex_unlock(&data.lock);

	if (kthread)
		wake_up_process(kthread);

	return csize;
}

/**
 * debug_window_write - Write function for "window" debugfs entry
 * @filp: The active open file structure for the debugfs "file"
 * @ubuf: The user buffer that contains the value to write
 * @cnt: The maximum number of bytes to write to "file"
 * @ppos: The current position in the debugfs "file"
 *
 * This function provides a write implementation for the "window" debugfs
 * interface to the hardware latency detetector. The window is the total time
 * in us that will be considered one sample period. Conceptually, windows
 * occur back-to-back and contain a sample width period during which
 * actual sampling occurs. Can be used to write a new total window size. It
 * is enfoced that any value written must be greater than the sample width
 * size, or an error results.
 */
static ssize_t
debug_window_write(struct file *filp, const char __user *ubuf,
		   size_t cnt, loff_t *ppos)
{
	char buf[U64STR_SIZE];
	int csize = min(cnt, sizeof(buf));
	u64 val = 0;
	int err = 0;

	memset(buf, '\0', sizeof(buf));
	if (copy_from_user(buf, ubuf, csize))
		return -EFAULT;

	buf[U64STR_SIZE-1] = '\0';			/* just in case */
	err = kstrtoull(buf, 10, &val);
	if (0 != err)
		return -EINVAL;

	mutex_lock(&data.lock);
	if (data.sample_width < val)
		data.sample_window = val;
	else
		csize = -EINVAL;
	mutex_unlock(&data.lock);

	return csize;
}

/*
 * Function pointers for the "count" debugfs file operations
 */
static const struct file_operations count_fops = {
	.open		= tracing_open_generic,
	.read		= hwlat_read,
	.write		= hwlat_write,
};

/*
 * Function pointers for the "width" debugfs file operations
 */
static const struct file_operations width_fops = {
	.open		= tracing_open_generic,
	.read		= hwlat_read,
	.write		= debug_width_write,
};

/*
 * Function pointers for the "window" debugfs file operations
 */
static const struct file_operations window_fops = {
	.open		= tracing_open_generic,
	.read		= hwlat_read,
	.write		= debug_window_write,
};

/**
 * init_debugfs - A function to initialize the debugfs interface files
 *
 * This function creates entries in debugfs for "hwlat_detector".
 * It creates the hwlat_detector directory in the tracing directory,
 * and within that directory is the count, width and window files to
 * change and view those values.
 */
static int init_debugfs(void)
{
	struct dentry *d_tracer;
	struct dentry *debug_dir;

	d_tracer = tracing_init_dentry();
	if (IS_ERR(d_tracer))
		return -ENOMEM;

	debug_dir = debugfs_create_dir("hwlat_detector", d_tracer);
	if (!debug_dir)
		goto err_debug_dir;

	debug_count = debugfs_create_file("count", 0440,
					  debug_dir, &data.count,
					  &count_fops);
	if (!debug_count)
		goto err_count;

	debug_sample_window = debugfs_create_file("window", 0640,
						      debug_dir, &data.sample_window,
						      &window_fops);
	if (!debug_sample_window)
		goto err_window;

	debug_sample_width = debugfs_create_file("width", 0644,
						     debug_dir, &data.sample_width,
						     &width_fops);
	if (!debug_sample_width)
		goto err_width;

	return 0;

err_width:
	debugfs_remove(debug_sample_window);
err_window:
	debugfs_remove(debug_count);
err_count:
	debugfs_remove(debug_dir);
err_debug_dir:
	return -ENOMEM;
}

static void hwlat_detector_tracer_start(struct trace_array *tr)
{
	int err;

	err = start_kthread();
	if (err)
		pr_err(BANNER "cannot start kthread\n");
}

static void hwlat_detector_tracer_stop(struct trace_array *tr)
{
	int err;

	err = stop_kthread();
	if (err)
		pr_err(BANNER "cannot stop kthread\n");
}

static bool hwlat_detector_enabled;

static int hwlat_detector_tracer_init(struct trace_array *tr)
{
	/* Only allow one instance to enable this */
	if (hwlat_detector_enabled)
		return -EBUSY;

	hwlat_detector_trace_array = tr;

	init_stats(tr);

	if (tracer_tracing_is_on(tr))
		hwlat_detector_tracer_start(tr);

	hwlat_detector_enabled = true;

	return 0;
}

static void hwlat_detector_tracer_reset(struct trace_array *tr)
{
	if (tracer_tracing_is_on(tr))
		hwlat_detector_tracer_stop(tr);

	/* the tracing threshold is static between runs */
	last_tracing_thresh = tracing_thresh;

	tracing_thresh = save_tracing_thresh;
	hwlat_detector_enabled = false;
}

static struct tracer hwlatdetect_tracer __read_mostly = {
	.name		= "hwlat_detector",
	.init		= hwlat_detector_tracer_init,
	.reset		= hwlat_detector_tracer_reset,
	.start		= hwlat_detector_tracer_start,
	.stop		= hwlat_detector_tracer_stop,
	.allow_instances = true,
};

static int __init init_hwlat_detector_tracer(void)
{
	register_tracer(&hwlatdetect_tracer);

	mutex_init(&data.lock);
	init_debugfs();
	return 0;
}
fs_initcall(init_hwlat_detector_tracer);
