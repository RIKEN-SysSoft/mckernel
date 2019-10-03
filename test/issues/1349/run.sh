#!/bin/bash
# run.sh COPYRIGHT FUJITSU LIMITED 2020
test_dir=$(dirname "${BASH_SOURCE[0]}")
. "${test_dir}/../../common.sh"

# init
meminfo="/sys/devices/virtual/mcos/mcos0/sys/devices/system/node/node0/meminfo"
"${MCEXEC}" 0 ./do_fork6 -nt 1 -t $((1000 * 10)) -mode-wait
sleep 1
exp_free_mem=`cat "$meminfo" | grep MemFree:`

# run
"${MCEXEC}" 0 ./do_fork6 -nt 1 -t $((1000 * 10)) -mode-wait
sleep 1
free_mem=`cat "$meminfo" | grep MemFree:`
if [ "$exp_free_mem" != "$free_mem" ]; then
	echo "NG: detected memory leak."
	exit -1
fi

"${MCEXEC}" 0 ./do_fork6 -nt 1 -t $((1000 * 10)) -mode-exit
sleep 1
free_mem=`cat "$meminfo" | grep MemFree:`
if [ "$exp_free_mem" != "$free_mem" ]; then
	echo "NG: detected memory leak."
	exit -1
fi

echo "OK"
