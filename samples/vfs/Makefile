# SPDX-License-Identifier: GPL-2.0-only
# List of programs to build
hostprogs-y := \
	test-fsinfo \
	test-fs-query \
	test-fsmount \
	test-mntinfo \
	test-statx

# Tell kbuild to always build the programs
always := $(hostprogs-y)

HOSTCFLAGS_test-fsinfo.o += -I$(objtree)/usr/include
HOSTLDLIBS_test-fsinfo += -lm
HOSTCFLAGS_test-mntinfo.o += -I$(objtree)/usr/include
HOSTLDLIBS_test-mntinfo += -lm

HOSTCFLAGS_test-fs-query.o += -I$(objtree)/usr/include
HOSTCFLAGS_test-fsmount.o += -I$(objtree)/usr/include
HOSTCFLAGS_test-statx.o += -I$(objtree)/usr/include
