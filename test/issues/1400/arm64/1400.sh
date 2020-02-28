#!/bin/sh
# 1400.sh COPYRIGHT FUJITSU LIMITED 2020

. $HOME/.mck_test_config

BOOTPARAM="-c 12-15 -m 1G@4 -O"
USELTP=1

. ../../../common.sh

PWD=`pwd`
LOGFILE="${PWD}/1400_log"
STOPFILE="./1400_stop"
LTPLIST="${PWD}/ltp_list.txt"

echo "issue-1400 test run."
echo "start-time: `date`"
stime=`date "+%s"`
failed=0

while :
do
	${MCEXEC} ./1400_arm64 > ${LOGFILE} 2>&1
	if [ $? -ne 0 ]; then
		echo "1400_arm64 failed."
		failed=1
		break
	fi

	pushd ${LTPBIN} > /dev/null
	while read line
	do
		${MCEXEC} ./${line} > ${LOGFILE} 2>&1
		if [ $? -ne 0 ]; then
			echo "${line} failed."
			failed=1
			break
		fi
	done < ${LTPLIST}
	popd > /dev/null

	if [ -e ${STOPFILE} ]; then
		rm -f ${STOPFILE}
		break
	fi

	if [ ${failed} -eq 1 ]; then
		break
	fi
done

echo "end-time: `date`"
etime=`date "+%s"`

run_time=$((${etime} - ${stime}))

if [ 43200 -le ${run_time} ]; then
	if [ ${failed} -eq 0 ]; then
		echo "issue-1400 test OK."
		rm -f ${LOGFILE}
	else
		echo "issue-1400 test NG."
	fi
else
	echo "issue-1400 test NG."
fi

mcstop
