#/bin/sh

USELTP=1
USEOSTEST=0

MCREBOOT=0
. ../../common.sh
BOOTPARAM="${BOOTPARAM} -e anon_on_demand"
mcreboot

PWD=`pwd`
STOPFILE="./1555_stop"
LOGFILE="${PWD}/1555_log"
LTPLIST="${PWD}/ltp_list"
TESTTIME=43200  # 6 hours

issue="1555"
echo "start-time: `date`"
stime=`date "+%s"`
failed=0
loops=0

while :
do
	sudo ${MCEXEC} ./C1555T01 > ${LOGFILE} 2>&1
	if [ $? -ne 0 ]; then
		echo "C1555T01 failed."
		failed=1
		break
	fi

	${IHKOSCTL} 0 clear_kmsg
	sudo ${MCEXEC} ./C1555T02 > ${LOGFILE} 2>&1
	if [ $? -ne 0 ]; then
		echo "C1555T02 failed."
		failed=1
		break
	fi

	dbg_cnt=`${IHKOSCTL} 0 kmsg | grep "ISSUE_1555" | wc -l`
	if [ ${dbg_cnt} -eq 0 ]; then
		echo "C1555T02 failed. Did not migrate in offload."
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

		ng=`grep FAIL ${LOGFILE} | wc -l`
    	if [ $ng -ne 0 ]; then
			echo "${line} failed."
			cat ${LOGFILE}
			failed=1
			break
		fi
	done < ${LTPLIST}
	popd > /dev/null

	let loops++

	if [ -e ${STOPFILE} ]; then
		rm -f ${STOPFILE}
		break
	fi

	etime=`date "+%s"`
	run_time=$((${etime} - ${stime}))
	if [ ${TESTTIME} -le ${run_time} ]; then
		break;
	fi

	if [ ${failed} -eq 1 ]; then
		break
	fi
done

echo "end-time: `date`"
etime=`date "+%s"`
run_time=$((${etime} - ${stime}))

if [ ${TESTTIME} -le ${run_time} ]; then
	if [ ${failed} -eq 0 ]; then
		echo "Issue#${issue} test OK."
		echo "Test cases run ${loops} times."
		rm -f ${LOGFILE}
	else
		echo "Issue#${issue} test NG."
		echo "Test cases run ${loops} times."
	fi
else
	echo "Issue#${issue} test NG."
	echo "Test cases run ${loops} times."
fi

