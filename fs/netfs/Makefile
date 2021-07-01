# SPDX-License-Identifier: GPL-2.0

netfs-y := \
	objects.o \
	read_helper.o \
	write_back.o \
	write_helper.o \
	write_prep.o
# dio_helper.o

netfs-$(CONFIG_NETFS_STATS) += stats.o

obj-$(CONFIG_NETFS_SUPPORT) := netfs.o
