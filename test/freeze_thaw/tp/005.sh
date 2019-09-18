#!/bin/env bash
# 005.sh COPYRIGHT FUJITSU LIMITED 2019
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
thaw
if [ $? -ne 0 ]; then
	echo "error: os status change(thaw)"
	exit 1
fi

"$mcexec" 0 "$hello" 0
if [ $? -ne 0 ]; then
	echo "error: execute user program"
	exit 1
fi

#
# fin
#
exit 0
