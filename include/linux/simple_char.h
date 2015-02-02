/*
 * A simple way to create character devices
 *
 * Copyright (c) 2015 Andy Lutomirski <luto@amacapital.net>
 *
 * Licensed under the GPLv2.
 */

#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/file.h>

struct simple_char_major;

struct simple_char_ops {
	bool (*reference)(void *private);
	const struct file_operations *fops;
};

struct simple_char_minor {
	struct simple_char_major *major;
	const struct simple_char_ops *ops;
	void *private;
	dev_t devt;
};

extern struct simple_char_minor *
simple_char_minor_create(struct simple_char_major *major,
			 const struct simple_char_ops *ops,
			 void *private);
extern void simple_char_minor_free(struct simple_char_minor *minor);

extern void simple_char_file_release(struct file *filep, struct kobject *kobj);

/* These exist only to support legacy classes that need their own major. */
extern struct simple_char_major *simple_char_major_create(const char *name);
extern void simple_char_major_free(struct simple_char_major *major);

