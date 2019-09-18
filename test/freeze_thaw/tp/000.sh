#!/bin/env bash
# 000.sh COPYRIGHT FUJITSU LIMITED 2019
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
freeze
if [ $? -ne 0 ]; then
	echo "error: os status change"
	exit 1
fi

#
# check
#
is_os_freeze
if [ $? -ne 0 ]; then
	echo "error: os status is not frozen"
	exit 1
fi

#
# fin
#
thaw
exit 0
