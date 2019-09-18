#!/bin/env bash
# 001.sh COPYRIGHT FUJITSU LIMITED 2019
script_dir="$(cd "$(dirname "${BASH_SOURCE:-${(%):-%N}}")"; pwd)"
. "$script_dir/../function"

#
# init
#
freeze
if [ $? -ne 0 ]; then
	echo "error: os status change(freeze)"
	exit 1
fi

is_os_freeze
if [ $? -ne 0 ]; then
	echo "error: os status is not frozen"
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

#
# check
#
is_os_running
if [ $? -ne 0 ]; then
	echo "error: os status is not running"
	exit 1
fi

#
# fin
#
exit 0
