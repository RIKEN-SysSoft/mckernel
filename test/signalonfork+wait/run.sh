#!/bin/bash
# run.sh COPYRIGHT FUJITSU LIMITED 2019
test_dir=$(dirname "${BASH_SOURCE[0]}")

#
# read config
#
. "${test_dir}/../common.sh"

#
# init
#
echo "@@@ initialize:"
seed="$RANDOM"
RANDOM=$seed
echo "seed for \$RANDOM=$seed"

meminfo="/sys/devices/virtual/mcos/mcos0/sys/devices/system/node/node0/meminfo"
"${MCEXEC}" 0 ./signalonfork_wait -nt 1 -t $((1000*5)) >/dev/null
sleep 1
exp_free_mem=`cat "$meminfo" | grep MemFree:`

#
# run
#
nr_loop=1000
echo "@@@ run signalonfork_wait: 1..$nr_loop"
for i in `seq 1 $nr_loop`
do
	echo -n "."
	new_line=$(($i % 100))
	if [ $new_line -eq 0 ]; then
		echo ""
	fi

	msec=$((1000 + $RANDOM % 500))
	"${MCEXEC}" 0 ./signalonfork_wait -nt 1 -t $msec >/dev/null
	sleep 1
	free_mem=`cat "$meminfo" | grep MemFree:`
	if [ "$exp_free_mem" != "$free_mem" ]; then
		echo ""
		echo "NG[$i]: detected memory leak."
		echo "before:"
		echo "  ${exp_free_mem}"
		echo "after:"
		echo "  ${free_mem}"
		exit -1
	fi
done
echo ""
echo "OK"
exit 0
