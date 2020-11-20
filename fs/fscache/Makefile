# SPDX-License-Identifier: GPL-2.0
#
# Makefile for general filesystem caching code
#

fscache-y := \
	cache.o \
	cache_init.o \
	cookie.o \
	dispatcher.o \
	fsdef.o \
	io.o \
	main.o \
	netfs.o \
	obj.o \
	object_bits.o

fscache-$(CONFIG_PROC_FS) += proc.o
fscache-$(CONFIG_FSCACHE_HISTOGRAM) += histogram.o
fscache-$(CONFIG_FSCACHE_OBJECT_LIST) += object-list.o
fscache-$(CONFIG_FSCACHE_STATS) += stats.o

obj-$(CONFIG_FSCACHE) := fscache.o
