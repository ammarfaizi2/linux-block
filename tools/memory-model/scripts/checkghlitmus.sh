#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
#
# Runs the C-language litmus tests having a maximum number of processes
# to run, defaults to 6.
#
# sh checkghlitmus.sh
#
# Run from the Linux kernel tools/memory-model directory.  See the
# parseargs.sh scripts for arguments.

. scripts/parseargs.sh

T=/tmp/checkghlitmus.sh.$$
trap 'rm -rf $T' 0
mkdir $T

# Clone the repository if it is not already present.
if test -d litmus
then
	:
else
	git clone https://github.com/paulmckrcu/litmus
	( cd litmus; git checkout origin/master )
fi

# Create a list of C-language litmus tests with "Result:" commands and
# no more than the specified number of processes.
find litmus -name '*.litmus' -exec grep -l -m 1 "^C " {} \; > $T/list-C
xargs < $T/list-C egrep -l '^ \* Result: (Never|Sometimes|Always)' > $T/list-C-result
xargs < $T/list-C-result grep -L "^P${LKMM_PROCS}" > $T/list-C-result-short

sed < $T/list-C-result-short -e 's,^.*$,if ! scripts/checklitmus.sh & ; then ret=1; fi,' > $T/script
ret=0
. $T/script
if test "$ret" -ne 0
then
	echo " ^^^ VERIFICATION MISMATCHES" 1>&2
else
	echo All litmus tests verified as was expected. 1>&2
fi
exit $ret
