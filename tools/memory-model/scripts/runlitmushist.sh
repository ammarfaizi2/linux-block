#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
#
# Runs the C-language litmus tests specified on standard input, using up
# to the specified number of CPUs (defaulting to all of them) and placing
# the results in the specified directory (defaulting to the same place
# the litmus test came from).
#
# sh runlitmushist.sh [ ncpu [ output-dir ] ]
#
# Run from the Linux kernel tools/memory-model directory.

nonline=`getconf _NPROCESSORS_ONLN`
ncpu=${1-$nonline}
if test -z "$2"
then
	dir=
else
	dir=$2/
fi
herdoptions=${LINUX_HERD_OPTIONS--conf linux-kernel.cfg}

T=/tmp/runlitmushist.sh.$$
trap 'rm -rf $T' 0
mkdir $T

if test -d litmus
then
	:
else
	echo Directory \"litmus\" missing, aborting run.
	exit 1
fi

# Prefixes for per-CPU scripts
for ((i=0;i<$ncpu;i++))
do
	echo dir="$dir" > $T/$i.sh
	echo T=$T >> $T/$i.sh
	echo herdoptions=\"$herdoptions\" >> $T/$i.sh
	cat << '___EOF___' >> $T/$i.sh
	runtest () {
		echo ' ... ' /usr/bin/time herd7 $herdoptions $1 '>' $dir$1.out '2>&1'
		/usr/bin/time herd7 $herdoptions $1 > $dir$1.out 2>&1
	}
___EOF___
done

awk -v q="'" -v b='\\' '
{
	print "echo `grep " q "^P[0-9]" b "+(" q " " $0 " | tail -1 | sed -e " q "s/^P" b "([0-9]" b "+" b ")(.*$/" b "1/" q "` " $0
}' | bash |
sort -k1n |
awk -v ncpu=$ncpu -v t=$T '
{
	print "runtest " $2 >> t "/" NR % ncpu ".sh";
}

END {
	for (i = 0; i < ncpu; i++) {
		print "sh " t "/" i ".sh > " t "/" i ".sh.out 2>&1 &";
		close(t "/" i ".sh");
	}
	print "wait";
}' | sh
cat $T/*.sh.out
