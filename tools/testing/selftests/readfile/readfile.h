// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
 * Copyright (c) 2021 The Linux Foundation
 *
 * Define the readfile system call number and
 * provide a "syscall" function for it.
 */
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <syscall.h>

//#ifndef __NR_readfile
//#define __NR_readfile	-1
//#endif

#define __NR_readfile	451

static inline int sys_readfile(int fd, const char *filename,
			       unsigned char *buffer, size_t bufsize, int flags)
{
	return syscall(__NR_readfile, fd, filename, buffer, bufsize, flags);
}
