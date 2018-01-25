// SPDX-License-Identifier: GPL-2.0
/*
 * trace events created on top of ftrace (functions).
 *
 * Copyright (C) 2018 VMware Inc, Steven Rostedt.
 */

#include <linux/ctype.h>
#include <linux/slab.h>

#include "trace.h"

#define FUNC_EVENT_SYSTEM "functions"
#define WRITE_BUFSIZE  4096

struct func_event {
	struct list_head		list;
	char				*func;
	struct trace_event_class	class;
	struct trace_event_call		call;
	struct ftrace_ops		ops;
	struct list_head		files;
};

struct func_file {
	struct list_head		list;
	struct trace_event_file		*file;
};

struct func_event_hdr {
	struct trace_entry	ent;
	unsigned long		ip;
	unsigned long		parent_ip;
};

static DEFINE_MUTEX(func_event_mutex);
static LIST_HEAD(func_events);

enum func_states {
	FUNC_STATE_INIT,
	FUNC_STATE_FUNC,
	FUNC_STATE_PARAM,
	FUNC_STATE_END,
	FUNC_STATE_ERROR,
};

static void free_func_event(struct func_event *func_event)
{
	if (!func_event)
		return;

	ftrace_free_filter(&func_event->ops);
	kfree(func_event->call.print_fmt);
	kfree(func_event->func);
	kfree(func_event);
}

static char *next_token(char **ptr, char *last)
{
	char *arg;
	char *str;

	if (!*ptr)
		return NULL;

	arg = *ptr;

	if (*last)
		*arg = *last;

	if (!*arg)
		return NULL;

	for (str = arg; *str; str++) {
		if (!isalnum(*str) && *str != '_')
			break;
	}
	if (*str) {
		if (str == arg)
			str++;
		*last = *str;
		*str = 0;
		*ptr = str;
		return arg;
	}

	*last = 0;
	*ptr = NULL;
	return arg;
}

static bool valid_name(const char *token)
{
	return isalpha(token[0]) || token[0] == '_';
}

static enum func_states
process_event(struct func_event *fevent, const char *token, enum func_states state)
{
	switch (state) {
	case FUNC_STATE_INIT:
		if (!valid_name(token))
			break;
		fevent->func = kstrdup(token, GFP_KERNEL);
		if (!fevent->func)
			break;
		return FUNC_STATE_FUNC;

	case FUNC_STATE_FUNC:
		if (token[0] != '(')
			break;
		return FUNC_STATE_PARAM;

	case FUNC_STATE_PARAM:
		if (token[0] != ')')
			break;
		return FUNC_STATE_END;

	default:
		break;
	}
	return FUNC_STATE_ERROR;
}

static void func_event_trace(struct trace_event_file *trace_file,
			     struct func_event *func_event,
			     unsigned long ip, unsigned long parent_ip,
			     struct pt_regs *pt_regs)
{
	struct func_event_hdr *entry;
	struct trace_event_call *call = &func_event->call;
	struct ring_buffer_event *event;
	struct ring_buffer *buffer;
	unsigned long irq_flags;
	int size;
	int pc;

	if (trace_trigger_soft_disabled(trace_file))
		return;

	local_save_flags(irq_flags);
	pc = preempt_count();

	size = sizeof(*entry);

	event = trace_event_buffer_lock_reserve(&buffer, trace_file,
						call->event.type,
						size, irq_flags, pc);
	if (!event)
		return;

	entry = ring_buffer_event_data(event);
	entry->ip = ip;
	entry->parent_ip = parent_ip;

	event_trigger_unlock_commit_regs(trace_file, buffer, event,
					 entry, irq_flags, pc, pt_regs);
}

static void
func_event_call(unsigned long ip, unsigned long parent_ip,
		    struct ftrace_ops *op, struct pt_regs *pt_regs)
{
	struct func_event *func_event;
	struct func_file *ff;

	func_event = container_of(op, struct func_event, ops);

	rcu_irq_enter_irqson();
	rcu_read_lock_sched_notrace();
	list_for_each_entry_rcu(ff, &func_event->files, list) {
		func_event_trace(ff->file, func_event, ip, parent_ip, pt_regs);
	}
	rcu_read_unlock_sched_notrace();
	rcu_irq_exit_irqson();
}



static enum print_line_t
func_event_print(struct trace_iterator *iter, int flags,
		 struct trace_event *event)
{
	struct func_event_hdr *entry;
	struct trace_seq *s = &iter->seq;

	entry = (struct func_event_hdr *)iter->ent;

	trace_seq_printf(s, "%ps->%ps()",
			 (void *)entry->parent_ip, (void *)entry->ip);
	trace_seq_putc(s, '\n');
	return trace_handle_return(s);
}

static struct trace_event_functions func_event_funcs = {
	.trace		= func_event_print,
};

static int func_event_define_fields(struct trace_event_call *event_call)
{
	struct func_event_hdr field;
	int ret;

	DEFINE_FIELD(unsigned long, ip, "__parent_ip", 0);
	DEFINE_FIELD(unsigned long, parent_ip, "__ip", 0);

	return 0;
}

static int enable_func_event(struct func_event *func_event,
			     struct trace_event_file *file)
{
	struct func_file *ff;
	int ret;

	ff = kmalloc(sizeof(*ff), GFP_KERNEL);
	if (!ff)
		return -ENOMEM;

	if (list_empty(&func_event->files)) {
		ret = register_ftrace_function(&func_event->ops);
		if (ret < 0) {
			kfree(ff);
			return ret;
		}
	}

	ff->file = file;
	/* Make sure file is visible before adding to the list */
	smp_wmb();
	list_add_rcu(&ff->list, &func_event->files);
	return 0;
}

static int disable_func_event(struct func_event *func_event,
			      struct trace_event_file *file)
{
	struct list_head *p, *n;
	struct func_file *ff;


	list_for_each_safe(p, n, &func_event->files) {
		ff = container_of(p, struct func_file, list);
		if (ff->file == file) {
			list_del_rcu(&ff->list);
			break;
		}
		ff = NULL;
	}

	if (!ff)
		return -ENODEV;

	if (list_empty(&func_event->files))
		unregister_ftrace_function(&func_event->ops);

	synchronize_sched();
	kfree(ff);

	return 0;
}

static int func_event_register(struct trace_event_call *event,
			       enum trace_reg type, void *data)
{
	struct func_event *func_event = event->data;
	struct trace_event_file *file = data;

	switch (type) {
	case TRACE_REG_REGISTER:
		return enable_func_event(func_event, file);
	case TRACE_REG_UNREGISTER:
		return disable_func_event(func_event, file);
	default:
		break;
	}

	return 0;
}

static int set_print_fmt(struct func_event *func_event)
{
	const char *fmt = "\"%pS->%pS()\", REC->__ip, REC->__parent_ip";

	func_event->call.print_fmt = kstrdup(fmt, GFP_KERNEL);
	if (!func_event->call.print_fmt)
		return -ENOMEM;

	return 0;
}

static int func_event_create(struct func_event *func_event)
{
	struct trace_event_call *call = &func_event->call;
	int ret;

	func_event->class.system = FUNC_EVENT_SYSTEM;
	call->class = &func_event->class;
	INIT_LIST_HEAD(&call->class->fields);
	call->event.funcs = &func_event_funcs;
	call->name = func_event->func;
	call->class->define_fields = func_event_define_fields;
	ret = set_print_fmt(func_event);
	if (ret < 0)
		return ret;
	ret = register_trace_event(&call->event);
	if (ret < 0)
		return ret;
	call->flags = TRACE_EVENT_FL_FUNC;
	call->class->reg = func_event_register;
	call->data = func_event;
	ret = trace_add_event_call(call);
	if (ret) {
		pr_info("Failed to register func event: %s\n", func_event->func);
		unregister_trace_event(&call->event);
	}
	return ret;
}

static int create_function_event(int argc, char **argv)
{
	struct func_event *func_event;
	enum func_states state = FUNC_STATE_INIT;
	char *token;
	char *ptr;
	char last;
	int ret = -EINVAL;
	int i;

	func_event = kzalloc(sizeof(*func_event), GFP_KERNEL);
	if (!func_event)
		return -ENOMEM;

	INIT_LIST_HEAD(&func_event->files);
	func_event->ops.func = func_event_call;
	func_event->ops.flags = FTRACE_OPS_FL_SAVE_REGS;

	mutex_lock(&func_event_mutex);
	for (i = 0; i < argc; i++) {
		ptr = argv[i];
		last = 0;
		for (token = next_token(&ptr, &last); token;
		     token = next_token(&ptr, &last)) {
			state = process_event(func_event, token, state);
			if (state == FUNC_STATE_ERROR)
				goto fail;
		}
	}
	if (state != FUNC_STATE_END)
		goto fail;

	ret = ftrace_set_filter(&func_event->ops, func_event->func,
				strlen(func_event->func), 0);
	if (ret < 0)
		goto fail;

	ret = func_event_create(func_event);
	if (ret < 0)
		goto fail;

	list_add_tail(&func_event->list, &func_events);
	mutex_unlock(&func_event_mutex);
	return 0;
 fail:
	mutex_unlock(&func_event_mutex);
	free_func_event(func_event);
	return ret;
}

static void *func_event_seq_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&func_event_mutex);
	return seq_list_start(&func_events, *pos);
}

static void *func_event_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return seq_list_next(v, &func_events, pos);
}

static void func_event_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&func_event_mutex);
}

static int func_event_seq_show(struct seq_file *m, void *v)
{
	struct func_event *func_event = v;

	seq_printf(m, "%s()\n", func_event->func);

	return 0;
}

static const struct seq_operations func_event_seq_op = {
	.start  = func_event_seq_start,
	.next   = func_event_seq_next,
	.stop   = func_event_seq_stop,
	.show   = func_event_seq_show
};

static int release_all_func_events(void)
{
	struct func_event *func_event, *n;
	int ret = 0;

	mutex_lock(&func_event_mutex);
	list_for_each_entry_safe(func_event, n, &func_events, list) {
		ret = trace_remove_event_call(&func_event->call);
		if (ret < 0)
			break;
		list_del(&func_event->list);
		free_func_event(func_event);
	}
	mutex_unlock(&func_event_mutex);
	return ret;
}

static int func_event_open(struct inode *inode, struct file *file)
{
	int ret;

	if ((file->f_mode & FMODE_WRITE) && (file->f_flags & O_TRUNC)) {
		ret = release_all_func_events();
		if (ret < 0)
			return ret;
	}

	return seq_open(file, &func_event_seq_op);
}

static ssize_t
func_event_write(struct file *filp, const char __user *ubuf,
		 size_t cnt, loff_t *ppos)
{
	return trace_parse_run_command(filp, ubuf, cnt, ppos,
				       create_function_event);
}

static const struct file_operations func_event_fops = {
	.open		= func_event_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
	.write		= func_event_write,
};

/* Make a tracefs interface for controlling probe points */
static __init int init_func_events(void)
{
	struct dentry *d_tracer;
	struct dentry *entry;

	d_tracer = tracing_init_dentry();
	if (IS_ERR(d_tracer))
		return 0;

	entry = trace_create_file("function_events", 0644, d_tracer, NULL,
				  &func_event_fops);

	/* Event list interface */
	if (!entry)
		pr_warn("Could not create tracefs 'function-events' entry\n");

	return 0;
}
fs_initcall(init_func_events);
