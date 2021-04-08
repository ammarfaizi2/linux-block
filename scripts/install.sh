#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 1995 by Linus Torvalds
# Copyright (C) 2021 Greg Kroah-Hartman
#
# Adapted from code in arch/i386/boot/Makefile by H. Peter Anvin
# Adapted from code in arch/i386/boot/install.sh by Russell King
# Adapted from code in arch/arm/boot/install.sh by Stuart Menefy
#
# "make install" script for Linux to be used by all architectures.
#
# Arguments:
#   $1 - kernel version
#   $2 - kernel image file
#   $3 - kernel map file
#   $4 - default install path (blank if root directory)
#
# Installs the built kernel image and map and symbol file in the specified
# install location.  If no install path is selected, the files will be placed
# in the root directory.
#
# The name of the kernel image will be "vmlinux-VERSION" for uncompressed
# kernels or "vmlinuz-VERSION' for compressed kernels.
#
# The kernel map file will be named "System.map-VERSION"
#
# Note, not all architectures seem to like putting the VERSION number in the
# file name, see below in the script for a list of those that do not.  For
# those that do not the "-VERSION" will not be present in the file name.
#
# If there is currently a kernel image or kernel map file present with the name
# of the file to be copied to the location, it will be renamed to contain a
# ".old" suffix.
#
# If ~/bin/${INSTALLKERNEL} or /sbin/${INSTALLKERNEL} is executable, execution
# will be passed to that program instead of this one to allow for distro or
# system specific installation scripts to be used.

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

base=$(basename "$2")
if [ "$base" = "bzImage" ] ||
   [ "$base" = "Image.gz" ] ||
   [ "$base" = "vmlinux.gz" ] ||
   [ "$base" = "vmlinuz" ] ||
   [ "$base" = "zImage" ] ; then
	# Compressed install
	echo "Installing compressed kernel"
	base=vmlinuz
else
	# Normal install
	echo "Installing normal kernel"
	base=vmlinux
fi

# Some architectures name their files based on version number, and
# others do not.  Call out the ones that do not to make it obvious.
case "${ARCH}" in
	ia64 | m68k | nios2 | powerpc | sparc | x86)
		version=""
		;;
	*)
		version="-${1}"
		;;
esac

install "$2" "$4"/"$base""$version"
install "$3" "$4"/System.map"$version"
sync

# Some architectures like to call specific bootloader "helper" programs:
case "${ARCH}" in
	arm)
		if [ -x /sbin/loadmap ]; then
			/sbin/loadmap
		else
			echo "You have to install it yourself"
		fi
		;;
	ia64)
		if [ -x /usr/sbin/elilo ]; then
			/usr/sbin/elilo
		fi
		;;
	powerpc)
		# powerpc installation can list other boot targets after the
		# install path that should be copied to the correct location
		path=$4
		shift 4
		while [ $# -ne 0 ]; do
			image_name=$(basename "$1")
			install "$1" "$path"/"$image_name"
			shift
		done;
		sync
		;;
	x86)
		if [ -x /sbin/lilo ]; then
			/sbin/lilo
		elif [ -x /etc/lilo/install ]; then
			/etc/lilo/install
		else
			echo "Cannot find LILO, ensure your bootloader knows of the new kernel image."
		fi
		;;
esac

# Some architectures like to call specific bootloader "helper" programs
# so let them have their own special command here
if [ -f "arch/$ARCH/boot/bootloader.sh" ] ; then
	sh arch/"$ARCH"/boot/bootloader.sh
fi
