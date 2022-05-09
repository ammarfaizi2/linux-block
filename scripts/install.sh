#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 1995 by Linus Torvalds
#
# Adapted from code in arch/i386/boot/Makefile by H. Peter Anvin
# Common code factored out by Masahiro Yamada

set -e

# Make sure the files actually exist
for file in "${KBUILD_IMAGE}" System.map
do
	if [ ! -f "${file}" ]; then
		echo >&2
		echo >&2 " *** Missing file: ${file}"
		echo >&2 ' *** You need to run "make" before "make install".'
		echo >&2
		exit 1
	fi
done

# installkernel(8) says the parameters are like follows:
#
#   installkernel version zImage System.map [directory]

set -- "${KERNELRELEASE}" "${KBUILD_IMAGE}" System.map "${INSTALL_PATH}"

# User/arch may have a custom install script
for file in "${HOME}/bin/${INSTALLKERNEL}"		\
	    "/sbin/${INSTALLKERNEL}"			\
	    "${srctree}/arch/${SRCARCH}/install.sh"	\
	    "${srctree}/arch/${SRCARCH}/boot/install.sh"
do
	if [ -x "${file}" ]; then
		exec "${file}" "$@"
	fi
done

echo "No install script found" >&2
exit 1
