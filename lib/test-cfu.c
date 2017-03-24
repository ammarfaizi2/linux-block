/*
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt) "cfu test: %s " fmt, __func__

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/module.h>

static char pat[2 * PAGE_SIZE];
static void run_test(int n, int m, char __user *up, char *kp)
{
	int i;
	for (i = 0; i < 4; i++) {
		int r;
		memset(kp, 0, 2 * PAGE_SIZE);
		r = __copy_from_user_inatomic(kp + i, up, m);
		if (m <= n) {
			if (r) {
				pr_err("bogus fault (%d, %d, %d)\n", r, m, n);
				return;
			}
		} else {
			if (r < m - n) {
				pr_err("claims too much (%d, %d, %d)\n", r, m, n);
				return;
			}
		}
		r = m - r;	/* claim to have copied that much */
		if (memcmp(kp + i, pat + PAGE_SIZE - n, r)) {
			int j;
			pr_err("crap in copy (%d, %d, %d)", r, m, n);
			for (j = 0; j < r; j++) {
				if (!kp[i+j]) {
					if (!memcmp(kp + i + j, pat + PAGE_SIZE, PAGE_SIZE)) {
						pr_cont(" only %d copied\n", j);
						return;
					}
					break;
				}
			}
			pr_cont("\n");
			return;
		}
		if (memcmp(kp + i + r, pat + PAGE_SIZE, PAGE_SIZE)) {
			pr_err("crap after copy (%d, %d, %d)\n", r, m, n);
			return;
		}
	}
}

static int __init cfu_test(void)
{
	char *kp;
	char __user *up;
	int i;

	kp = kmalloc(PAGE_SIZE * 2, GFP_KERNEL);
	if (!kp)
		return -EAGAIN;

	up = (char __user *)vm_mmap(NULL, 0, 2 * PAGE_SIZE,
			    PROT_READ | PROT_WRITE | PROT_EXEC,
			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
	if (IS_ERR(up)) {
		pr_err("Failed to allocate user memory\n");
		kfree(kp);
		return -EAGAIN;
	}
	vm_munmap((unsigned long)up + PAGE_SIZE, PAGE_SIZE);

	for (i = 0; i < PAGE_SIZE; i++)
		pat[i] = 128 | i;
	if (copy_to_user(up, pat, PAGE_SIZE)) {
		pr_err("failed to copy to user memory\n");
		goto out;
	}

	for (i = 0; i <= 128; i++) {
		int j;
		pr_err("trying %d\n", i);
		for (j = 0; j <= 128; j++)
			run_test(i, j, up + PAGE_SIZE - i, kp);
	}

out:
	vm_munmap((unsigned long)up, PAGE_SIZE);
	kfree(kp);
	return -EAGAIN;
}

module_init(cfu_test);
MODULE_LICENSE("GPL");
