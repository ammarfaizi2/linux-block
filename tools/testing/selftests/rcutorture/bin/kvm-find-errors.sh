#!/bin/sh
#
# Invoke a text editor on all console.log files for all runs with diagnostics,
# that is, on all such files having a console.log.diags counterpart.
# Note that both console.log.diags and console.log are passed to the
# editor (currently defaulting to "vi"), allowing the user to get an
# idea of what to search for in the console.log file.
#
# Usage: kvm-find-errors.sh directory
#
# The "directory" above should end with the date/time directory, for example,
# "tools/testing/selftests/rcutorture/res/2018.02.25-14:27:27".

rundir="${1}"
if test -z "$rundir" -o ! -d "$rundir"
then
	echo Usage: $0 directory
fi
editor=${EDITOR-vi}
files=
for i in ${rundir}/*/console.log
do
	if test -r $i.diags
	then
		files="$files $i.diags $i"
	fi
done
$editor $files
