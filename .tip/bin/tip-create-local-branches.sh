#!/bin/sh

. $(dirname "$0")/tip-lib

check_master

BS=`(git branch -a | grep origin | grep -v master | grep -v HEAD | grep -v " linus" | sed s@origin/@@ | sed s@remotes/@@; \
    git branch | grep -v master | grep -v HEAD | grep -v " linus") | sort | uniq -u`

for B in $BS
do
    # Check if the unique branch is a local one
    L=`git branch | grep " $B$"`
    if [ -z "$L" ]
    then
	git branch $B origin/$B
    fi
done
