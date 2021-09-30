# SPDX-License-Identifier: GPL-2.0

netfs-y := \
	buffered_read.o \
	buffered_flush.o \
	buffered_write.o \
	crypto.o \
	direct_read.o \
	direct_write.o \
	io.o \
	main.o \
	misc.o \
	objects.o \
	output.o \
	truncate.o

netfs-$(CONFIG_NETFS_STATS) += stats.o

obj-$(CONFIG_NETFS_SUPPORT) := netfs.o
