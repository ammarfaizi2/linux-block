#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
#
# Run a series of tests on remote systems under KVM.
#
# Usage: kvm-remote.sh "systems" [ <kvm.sh args> ]
#	 kvm-remote.sh "systems" /path/to/old/run [ <kvm-again.sh args> ]
#
# Copyright (C) 2021 Facebook, Inc.
#
# Authors: Paul E. McKenney <paulmck@kernel.org>

scriptname=$0
args="$*"

if ! test -d tools/testing/selftests/rcutorture/bin
then
	echo $scriptname must be run from top-level directory of kernel source tree.
	exit 1
fi

KVM="`pwd`/tools/testing/selftests/rcutorture"; export KVM
PATH=${KVM}/bin:$PATH; export PATH
. functions.sh

starttime="`get_starttime`"

systems="$1"
if test -z "$systems"
then
	echo $scriptname: Empty list of systems will go nowhere good, giving up.
	exit 1
fi
shift

# Pathnames:
# T:	  /tmp/kvm-again.sh.$$
# resdir: /tmp/kvm-again.sh.$$/res
# rundir: /tmp/kvm-again.sh.$$/res/$ds ("-remote" suffix)
# oldrun: `pwd`/tools/testing/.../res/$otherds
#
# Pathname segments:
# TD:	  kvm-again.sh.$$
# ds:	  yyyy.mm.dd-hh.mm.ss-remote

TD=kvm-again.sh.$$
T=${TMPDIR-/tmp}/$TD
trap 'rm -rf $T' 0
mkdir $T

resdir="$T/res"
ds=`date +%Y.%m.%d-%H.%M.%S`-remote
rundir=$resdir/$ds
echo $scriptname $args
if echo $1 | grep -q '^--'
then
	# Fresh build.  Create a datestamp unless the caller supplied one.
	datestamp="`echo "$@" | awk -v ds="$ds" '{
		for (i = 1; i < NF; i++) {
			if ($i == "--datestamp") {
				ds = "";
				break;
			}
		}
		if (ds != "")
			print "--datestamp " ds;
	}'`"
	kvm.sh "$@" $datestamp --buildonly > $T/kvm.sh.out 2>&1
	ret=$?
	if test "$ret" -ne 0
	then
		echo $scriptname: kvm.sh failed exit code $?
		cat $T/kvm.sh.out
		exit 2
	fi
	oldrun="`grep -m 1 "^Results directory: " $T/kvm.sh.out | awk '{ print $3 }'`"
	# We are going to run this, so remove the buildonly files.
	rm -f "$oldrun"/*/buildonly
	kvm-again.sh $oldrun --dryrun --remote --rundir "$rundir" > $T/kvm-again.sh.out 2>&1
	ret=$?
	if test "$ret" -ne 0
	then
		echo $scriptname: kvm-again.sh failed exit code $?
		cat $T/kvm-again.sh.out
		exit 2
	fi
else
	# Re-use old run.
	oldrun="$1"
	if ! echo $oldrun | grep -q '^/'
	then
		oldrun="`pwd`/$oldrun"
	fi
	shift
	kvm-again.sh "$oldrun" "$@" --dryrun --remote --rundir "$rundir" > $T/kvm-again.sh.out 2>&1
	ret=$?
	if test "$ret" -ne 0
	then
		echo $scriptname: kvm-again.sh failed exit code $?
		cat $T/kvm-again.sh.out
		exit 2
	fi
	cp -a "$rundir" "$KVM/res/"
	oldrun="$KVM/res/$ds"
fi
touch "$oldrun/log"
echo $scriptname $args >> "$oldrun/log"

# Create the kvm-remote-N.sh scripts in the bin directory.
awk < "$rundir"/scenarios -v dest="$T/bin" -v rundir="$rundir" '
{
	n = $1;
	sub(/\./, "", n);
	fn = dest "/kvm-remote-" n ".sh"
	scenarios = "";
	for (i = 2; i <= NF; i++)
		scenarios = scenarios " " $i;
	print "kvm-test-1-run-batch.sh" scenarios > fn;
	print "rm " rundir "/remote.run" >> fn;
}'
chmod +x $T/bin/kvm-remote-*.sh
( cd "`dirname $T`"; tar -chzf $T/binres.tgz "$TD/bin" "$TD/res" )

# Check first to avoid the need for cleanup for system-name typos
for i in $systems
do
	echo -n $i: ""
	ssh $i date
	ret=$?
	if test "$ret" -ne 0
	then
		echo System $i unreachable, giving up.
		exit 4
	fi
done

# Download and expand the tarball on all systems.
for i in $systems
do
	cat $T/binres.tgz | ssh $i "cd /tmp; tar -xzf -"
	ret=$?
	if test "$ret" -ne 0
	then
		echo Unable to download $T/binres.tgz to system $i, giving up.
		exit 10
	fi
done

# Function to start batches on idle remote $systems
#
# Usage: startbatches curbatch nbatches
#
# Batches are numbered starting at 1.  Returns the next batch to start.
startbatches () {
	local curbatch="$1"
	local nbatches="$2"
	local ret

	# Each pass through the following loop examines one system.
	for i in $systems
	do
		if test "$curbatch" -gt "$nbatches"
		then
			echo $((nbatches + 1))
			return 0
		fi
		if ssh "$i" "test -f \"$resdir/$ds/remote.run\"" 1>&2
		then
			continue # System still running last test, skip.
		fi
		ssh "$i" "cd \"$resdir/$ds\"; touch remote.run; PATH=\"$T/bin:$PATH\" nohup kvm-remote-$curbatch.sh > kvm-remote-$curbatch.sh.out 2>&1 &" 1>&2
		ret=$?
		if test "$ret" -ne 0
		then
			echo ssh $i failed: exitcode $ret 1>&2
			exit 11
		fi
		echo " ----" System $i Batch `head -n $curbatch < "$rundir"/scenarios | tail -1` `date` 1>&2
		curbatch=$((curbatch + 1))
	done
	echo $curbatch
}

# Launch all the scenarios.
nbatches="`wc -l "$rundir"/scenarios | awk '{ print $1 }'`"
curbatch=1
while test "$curbatch" -le "$nbatches"
do
	curbatch="`startbatches $curbatch $nbatches`"
	sleep 30
done

# Wait for all remaining scenarios to complete and collect results.
for i in $systems
do
	while ssh "$i" "test -f \"$resdir/$ds/remote.run\""
	do
		sleep 30
	done
	( cd "$oldrun"; ssh $i "cd $rundir; tar -czf - kvm-remote-*.sh.out */console.log */kvm-test-1-run*.sh.out */qemu_pid */qemu-retval; cd /tmp; rf -rf $rundir > /dev/null 2>&1" | tar -xzf - )
done

kvm-end-run-stats.sh "$oldrun" "$starttime"
ret=$? # @@@

# @@@ Gather up output and do recheck stuff.
# @@@ Maybe convert end of kvm-again.sh to a .-able bash file?

echo oldrun = $oldrun # @@@
echo resdir = $resdir # @@@  Contains all scenarios, sibling to "bin".
echo rundir = $rundir # @@@  "build.remoterun" lives here.
echo Tarball in $T/binres.tgz # @@@
echo Hit enter to terminate: # @@@
read a # @@@
echo Terminated. # @@@
exit $ret # @@@
