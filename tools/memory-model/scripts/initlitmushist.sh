#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
#
# Runs the C-language litmus tests having a maximum number of processes
# to run, defaults to 6.  Places the output for each .litmus file in
# the corresponding .litmus.out file, and does not judge the result.
#
# sh initlitmushist.sh [ maxprocesses ]
#
# Run from the Linux kernel tools/memory-model directory.

np=${1-6}
herdoptions=${LINUX_HERD_OPTIONS--conf linux-kernel.cfg}

T=/tmp/initlitmushist.sh.$$
trap 'rm -rf $T' 0
mkdir $T

if test -d litmus
then
	:
else
	git clone https://github.com/paulmckrcu/litmus
	( cd litmus; git checkout origin/master )
fi
find litmus -name '*.litmus' -exec grep -l -m 1 "^C " {} \; > $T/list-C
xargs < $T/list-C grep -L "^P${np}" > $T/list-C-short

sed < $T/list-C-short -e 's,^.*$,/usr/bin/time herd7 $herdoptions & > &.out,' > $T/script
. $T/script > $T/script.out 2>&1
cat $T/script.out

exit 0
