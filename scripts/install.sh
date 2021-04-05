#!/bin/sh
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 1995 by Linus Torvalds
#
# Adapted from code in arch/i386/boot/Makefile by H. Peter Anvin
#
# "make install" script for i386 architecture
#
# Arguments:
#   $1 - kernel version
#   $2 - kernel image file
#   $3 - kernel map file
#   $4 - default install path (blank if root directory)
#

verify () {
	if [ ! -f "$1" ]; then
		echo ""                                                   1>&2
		echo " *** Missing file: $1"                              1>&2
		echo ' *** You need to run "make" before "make install".' 1>&2
		echo ""                                                   1>&2
		exit 1
 	fi
}

install () {
	install_source=${1}
	install_target=${2}

	echo "installing '${install_source}' to '${install_target}'"

	# if the target is already present, move it to a .old filename
	if [ -f "${install_target}" ]; then
		mv "${install_target}" "${install_target}".old
	fi
	cat "${install_source}" > "${install_target}"
}

# Make sure the files actually exist
verify "$2"
verify "$3"

# User may have a custom install script

if [ -x ~/bin/"${INSTALLKERNEL}" ]; then exec ~/bin/"${INSTALLKERNEL}" "$@"; fi
if [ -x /sbin/"${INSTALLKERNEL}" ]; then exec /sbin/"${INSTALLKERNEL}" "$@"; fi

# Default install - same as make zlilo
install "$2" "$4"/vmlinuz
install "$3" "$4"/System.map

if [ -x /sbin/lilo ]; then
       /sbin/lilo
elif [ -x /etc/lilo/install ]; then
       /etc/lilo/install
else
       sync
       echo "Cannot find LILO."
fi
