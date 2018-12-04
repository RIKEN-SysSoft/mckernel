#!/bin/sh

MCK_DIR=/home/satoken/ppos
REP_NUM=100

for i in `seq 1 ${REP_NUM}`
do
	sudo ${MCK_DIR}/sbin/mcstop+release.sh
	sleep 1
	sudo ${MCK_DIR}/sbin/mcreboot.sh

	if [ $? -ne 0 ]; then
		echo "[NG] failed to boot Mckernel  :${i}"
		exit 1
	fi
done

echo "[OK] succeed to boot McKernel ${i} times"
