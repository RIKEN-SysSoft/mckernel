#!/bin/env bash
# 1xx.sh COPYRIGHT FUJITSU LIMITED 2019
script_dir="$(cd "$(dirname "${BASH_SOURCE:-${(%):-%N}}")"; pwd)"
. "$script_dir/../function"
tp_num=`basename $0 .sh`
cpu=$(($tp_num - 100))

#
# init
#
freeze
if [ $? -ne 0 ]; then
	echo "error: os status change"
	exit 1
fi

is_os_freeze
if [ $? -ne 0 ]; then
	echo "error: os status is not frozen"
	exit 1
fi

log="$work_dir/${cpu}.txt"
rm -f "$log"

#
# run
#
"$mcexec" -c "$cpu" 0 "$hello" "$cpu" > "$log"&
sleep 1

string=`cat "$log"`
if [ -n "$string" ]; then
	echo "error: log file is not empty"
	exit 1
fi

thaw
sleep 1

string=`cat "$log"`
if [ -z "$string" ]; then
	echo "error: log file is empty"
	exit 1
fi

#
# fin
#
exit 0
