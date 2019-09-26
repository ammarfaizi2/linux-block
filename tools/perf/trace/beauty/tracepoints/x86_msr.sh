#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1

if [ $# -ne 1 ] ; then
	arch_x86_header_dir=tools/arch/x86/include/asm/
else
	arch_x86_header_dir=$1
fi

x86_msr_index=${arch_x86_header_dir}/msr-index.h

# Support all later, with some hash table, for now chop off
# Just the ones starting with 0x00000 so as to have a simple
# array.

printf "static const char *x86_MSRs[] = {\n"
regex='^[[:space:]]*#[[:space:]]*define[[:space:]]+MSR_([[:alnum:]][[:alnum:]_]+)[[:space:]]+(0x00000[[:xdigit:]]+)[[:space:]]*.*'
egrep $regex ${x86_msr_index} | \
	sed -r "s/$regex/\2 \1/g" | sort -n | \
	xargs printf "\t[%s] = \"%s\",\n"
printf "};\n"
