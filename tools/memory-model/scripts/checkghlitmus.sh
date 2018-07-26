#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
#
# Runs the C-language litmus tests having a maximum number of processes
# to run, defaults to 6.
#
# sh checkghlitmus.sh [ maxprocesses ]
#
# Run from the Linux kernel tools/memory-model directory.

np=${1-6}

T=/tmp/checkghlitmus.sh.$$
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
xargs < $T/list-C egrep -l '^ \* Result: (Never|Sometimes|Always)' > $T/list-C-result
xargs < $T/list-C-result grep -L "^P${np}" > $T/list-C-result-short

# Find the checklitmus script.  If it is not where we expect it, then
# assume that the caller has the PATH environment variable set
# appropriately.
if test -x scripts/checklitmus.sh
then
	clscript=scripts/checklitmus.sh
else
	clscript=checklitmus.sh
fi

sed < $T/list-C-result-short -e 's,^.*$,if ! '"$clscript"' & ; then ret=1; fi,' > $T/script
ret=0
. $T/script
if test "$ret" -ne 0
then
	echo " ^^^ VERIFICATION MISMATCHES"
else
	echo All litmus tests verified as was expected.
fi
exit $ret
