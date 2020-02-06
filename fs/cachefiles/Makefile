# SPDX-License-Identifier: GPL-2.0
#
# Makefile for caching in a mounted filesystem
#

cachefiles-y := \
	bind.o \
	content-map.o \
	daemon.o \
	interface.o \
	io.o \
	key.o \
	main.o \
	namei.o \
	security.o \
	xattr.o

cachefiles-$(CONFIG_CACHEFILES_HISTOGRAM) += proc.o

obj-$(CONFIG_CACHEFILES) := cachefiles.o
