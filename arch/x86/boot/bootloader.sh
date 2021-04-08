#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# x86 default bootloader setup
#
# Defaults to LILO as that's the historical bootloader
# Maybe someday we can update this.

echo "hello from bootloader.sh!"

if [ -x /sbin/lilo ]; then
	/sbin/lilo
elif [ -x /etc/lilo/install ]; then
	/etc/lilo/install
else
	echo "Cannot find LILO, ensure your bootloader knows of the new kernel image."
fi
