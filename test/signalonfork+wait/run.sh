#!/bin/bash
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
"${MCEXEC}" 0 ./signalonfork_wait -nt 1 -t $((1000*5))
sleep 1
exp_free_mem=`cat "$meminfo" | grep MemFree:`

#
# run
#
for i in `seq 1 100`
do
	msec=$((1000 + $RANDOM % 500))
	echo "@@@ run signalonfork_wait:($i) wait=$msec"
	"${MCEXEC}" 0 ./signalonfork_wait -nt 1 -t $msec
	sleep 1
	free_mem=`cat "$meminfo" | grep MemFree:`
	if [ "$exp_free_mem" != "$free_mem" ]; then
		echo "NG: detected memory leak."
		echo "before:"
		echo "  ${exp_free_mem}"
		echo "after:"
		echo "  ${free_mem}"
		exit -1
	fi
done
echo "OK"
exit 0
