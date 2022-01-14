# SPDX-License-Identifier: GPL-2.0

netfs-y := \
	direct.o \
	main.o \
	read_helper.o

netfs-$(CONFIG_NETFS_STATS) += stats.o

obj-$(CONFIG_NETFS_SUPPORT) := netfs.o
