#!/bin/env bash
# 200.sh COPYRIGHT FUJITSU LIMITED 2019
script_dir="$(cd "$(dirname "${BASH_SOURCE:-${(%):-%N}}")"; pwd)"
. "$script_dir/../function"

#
# init
#
is_os_running
if [ $? -ne 0 ]; then
	echo "error: os status is not running"
	exit 1
fi

#
# run
#
sh "$script_dir/200_fork.sh"&
fork_pid=$!

echo "freeze-thaw:"
for i in `seq 1 20`
do
	echo -n "."
	freeze
	if [ $? -ne 0 ]; then
		echo "error: freeze($i)"
		exit 1
	fi

	thaw
	if [ $? -ne 0 ]; then
		echo "error: thaw($i)"
		exit 1
	fi
done
echo ""

#
# fin
#
kill $fork_pid
sleep 1
exit 0
