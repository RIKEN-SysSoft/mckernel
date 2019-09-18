#!/bin/env bash
# 002.sh COPYRIGHT FUJITSU LIMITED 2019
script_dir="$(cd "$(dirname "${BASH_SOURCE:-${(%):-%N}}")"; pwd)"
. "$script_dir/../function"

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

#
# run
#
freeze
if [ $? -ne 0 ]; then
	echo "error: os status change"
	exit 1
fi

#
# fin
#
thaw
exit 0
