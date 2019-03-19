#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
#
# Convert the specified C-language litmus test to the assembly-language
# equivalent specified by the designated .map file name fragment (omitting
# the "Linux2" at the front and the ".map" at the end).  Note that litmus
# tests containing complex primitives (including locking and RCU) cannot
# be translated to assembly language.  Run herd on the assembly-language
# litmus test and complain if it is not consistent with the Result line
# in the original C-language litmus test.
#
# Usage:
#	checklitmushw.sh file.litmus
#
# Run this in the directory containing the memory model, specifying the
# pathname of the litmus test to check.  The caller is expected to have
# properly set up the LKMM environment variables.  Note that because we
# are running a hardware model, LKMM_HERD_OPTIONS is ignored.
#
# This script relies on the current defacto convention that the .cat file
# name is the same as the portion of the .map file name following the
# "Linux2", but with uppercase characters converted to lower case.
#
# Copyright IBM Corporation, 2019
#
# Author: Paul E. McKenney <paulmck@linux.vnet.ibm.com>

T=/tmp/checklitmushw.sh.$$
trap 'rm -rf $T' 0 2
mkdir $T

litmus=$1
catfile="`echo $LKMM_HW_MAP_FILE | tr '[A-Z]' '[a-z]'`.cat"
mapfile="Linux2${LKMM_HW_MAP_FILE}.map"
themefile="$T/${LKMM_HW_MAP_FILE}.theme"
herdoptions="-model $LKMM_HW_CAT_FILE"
hwlitmus=`echo $litmus | sed -e 's/\.litmus$/.'${LKMM_HW_MAP_FILE}'.litmus/'`
hwlitmusfile=`echo $hwlitmus | sed -e 's,^.*/,,'`

if test -f "$litmus" -a -r "$litmus"
then
	:
else
	echo ' --- ' error: \"$litmus\" is not a readable file
	exit 255
fi
exclude="^[[:space:]]*\("
exclude="${exclude}spin_lock(\|spin_unlock(\|spin_trylock(\|spin_is_locked("
exclude="${exclude}\|rcu_read_lock(\|rcu_read_unlock("
exclude="${exclude}\|synchronize_rcu(\|synchronize_rcu_expedited("
exclude="${exclude}\|srcu_read_lock(\|srcu_read_unlock("
exclude="${exclude}\|synchronize_srcu(\|synchronize_srcu_expedited("
exclude="${exclude}\)"
if grep -q $exclude $litmus
then
	echo ' --- ' error: \"$litmus\" contains locking, RCU, or SRCU
	exit 254
fi

gen_theme7 -n 10 -map $mapfile -call Linux.call > $themefile
jingle7 -theme $themefile $litmus > $T/$hwlitmusfile 2> $T/$hwlitmusfile.jingle7.out
/usr/bin/time $LKMM_TIMEOUT_CMD herd7 -model $catfile $T/$hwlitmusfile > $LKMM_DESTDIR/$hwlitmus.out 2>&1

scripts/judgelitmus.sh $litmus $LKMM_DESTDIR/$hwlitmus.out
