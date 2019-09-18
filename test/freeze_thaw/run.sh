#!/bin/env bash
# run.sh COPYRIGHT FUJITSU LIMITED 2019
script_dir="$(cd "$(dirname "${BASH_SOURCE:-${(%):-%N}}")"; pwd)"
. "$script_dir/../common.sh"
ln -sf "$BIN/mcexec"
ln -sf "$SBIN/ihkosctl"

cd "$script_dir/tp"
for tp in `find . -regex './[0-9][0-9][0-9]\.sh$'`
do
	echo "@@@ $tp @@@"
	sh "$tp"
	if [ $? -eq 0 ]; then
		echo "OK"
	else
		echo "NG"
	fi
done
