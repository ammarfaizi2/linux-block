// SPDX-License-Identifier: GPL-2.0
#include <linux/cpufreq.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

extern const struct seq_operations cpuinfo_op;
#ifdef CONFIG_X86
extern const struct seq_operations cpuinfo_local_op;
const struct seq_operations * const clop = &cpuinfo_local_op;
#else
const struct seq_operations * const clop = &cpuinfo_op;
#endif
static int cpuinfo_local_open(struct inode *inode, struct file *file)
{
	return seq_open(file, clop);
}

static const struct proc_ops cpuinfo_local_proc_ops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= cpuinfo_local_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};

static int __init proc_cpuinfo_local_init(void)
{
	proc_create("cpuinfo_local", 0, NULL, &cpuinfo_local_proc_ops);
	return 0;
}
fs_initcall(proc_cpuinfo_local_init);
