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
elog="$work_dir/${cpu}.err.txt"
rm -f "$log" "$elog"

#
# run
#
"$mcexec" -c "$cpu" 0 "$hello" "$cpu" >"$log" 2>"$elog" &
sleep 1

string=`cat "$log"`
if [ -n "$string" ]; then
	echo "error: log file is not empty:1"
	exit 1
fi

thaw
sleep 1

string=`cat "$log"`
if [ -n "$string" ]; then
	echo "error: log file is not empty:2"
	exit 1
fi

grep -q "prepare: Resource temporarily unavailable" "$elog"
if [ $? -ne 0 ]; then
	echo "error: unexpected errno"
	exit 1
fi

#
# fin
#
exit 0
