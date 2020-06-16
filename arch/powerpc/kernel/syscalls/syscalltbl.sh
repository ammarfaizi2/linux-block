#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

in="$1"
out="$2"
my_abis=`echo "($3)" | tr ',' '|'`
my_abi="$4"
offset="$5"
spu_table="$6"

emit() {
	t_nxt="$1"
	t_nr="$2"
	t_entry="$3"

	while [ $t_nxt -lt $t_nr ]; do
		printf "__SYSCALL(%s,sys_ni_syscall)\n" "${t_nxt}"
		t_nxt=$((t_nxt+1))
	done
	printf "__SYSCALL(%s,%s)\n" "${t_nxt}" "${t_entry}"
}

grep -E "^[0-9A-Fa-fXx]+[[:space:]]+${my_abis}" "$in" | sort -n | (
	nxt=0
	if [ -z "$offset" ]; then
		offset=0
	fi

	while read nr abi name entry compat ; do
		if [ "$my_abi" = "c32" ] && [ ! -z "$compat" ]; then
			emit $((nxt+offset)) $((nr+offset)) $compat
			nxt=$((nr+1))
		elif [ "$my_abi" = "spu" ]; then
			grep -E "^$nr[[:space:]]+$name[[:space:]]+spu[[:space:]]*$" "$spu_table" > /dev/null
			if [ $? -eq 0 ]; then
				emit $((nxt+offset)) $((nr+offset)) $entry
				nxt=$((nr+1))
			fi
		else
			emit $((nxt+offset)) $((nr+offset)) $entry
			nxt=$((nr+1))
		fi
	done
) > "$out"
