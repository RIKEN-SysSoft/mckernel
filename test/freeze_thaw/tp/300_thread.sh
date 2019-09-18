#!/bin/env bash
# 300_thread.sh COPYRIGHT FUJITSU LIMITED 2019
script_dir="$(cd "$(dirname "${BASH_SOURCE:-${(%):-%N}}")"; pwd)"
. "$script_dir/../function"

while true
do
	"$mcexec" 0 "$thread" 100 >/dev/null 2>&1
done
