#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
#
# Run a herd test and check the result against a "Result:" comment within
# the litmus test.  If the verification result does not match that specified
# in the litmus test, this script prints an error message prefixed with
# "!!!" and exits with a non-zero status.  It also outputs verification
# results to a file whose name is that of the specified litmus test, but
# with ".out" appended.
#
# Usage:
#	checklitmus.sh file.litmus
#
# Run this in the directory containing the memory model, specifying the
# pathname of the litmus test to check.
#
# Copyright IBM Corporation, 2018
#
# Author: Paul E. McKenney <paulmck@linux.vnet.ibm.com>

litmus=$1
herdoptions=${LKMM_HERD_OPTIONS--conf linux-kernel.cfg}

if test -f "$litmus" -a -r "$litmus"
then
	:
else
	echo ' --- ' error: \"$litmus\" is not a readable file
	exit 255
fi
if grep -q '^ \* Result: ' $litmus
then
	outcome=`grep -m 1 '^ \* Result: ' $litmus | awk '{ print $3 }'`
else
	outcome=specified
fi

echo Herd options: $herdoptions > $LKMM_DESTDIR/$litmus.out
/usr/bin/time $LKMM_TIMEOUT_CMD herd7 $herdoptions $litmus >> $LKMM_DESTDIR/$litmus.out 2>&1
grep "Herd options:" $litmus.out
grep '^Observation' $litmus.out
if grep -q '^Observation' $litmus.out
then
	:
else
	cat $litmus.out
	echo ' !!! Verification error' $litmus
	echo ' !!! Verification error' >> $litmus.out 2>&1
	exit 255
fi
if test "$outcome" = DEADLOCK
then
	echo grep 3 and 4
	if grep '^Observation' $litmus.out | grep -q 'Never 0 0$'
	then
		ret=0
	else
		echo " !!! Unexpected non-$outcome verification" $litmus
		echo " !!! Unexpected non-$outcome verification" >> $litmus.out 2>&1
		ret=1
	fi
elif grep '^Observation' $litmus.out | grep -q $outcome || test "$outcome" = Maybe
then
	ret=0
else
	echo " !!! Unexpected non-$outcome verification" $litmus
	echo " !!! Unexpected non-$outcome verification" >> $litmus.out 2>&1
	ret=1
fi
tail -2 $litmus.out | head -1
exit $ret
