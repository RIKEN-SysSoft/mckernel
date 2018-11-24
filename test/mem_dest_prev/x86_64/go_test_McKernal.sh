#!/bin/sh

# read config
source ./config

#logfile="./result/test_result.log"

# mcexec processのkill
./utils/kill_mcexec.sh &> /dev/null

for test_case in `ls -1 ./testcases/*.txt`
do
	# read testcase param
	source ${test_case}
	case_name=`basename ${test_case} .txt`
	echo "####################"
	echo "Test No:${case_name}"

	# Out-of-range address Test(Before correspondence)
	echo ">>> Out-of-range address Test(Before correspondence) Start"

	# stop mckernel
	sudo ${MCMOD_DIR}/sbin/mcstop+release.sh
	sleep 1
	# boot mckernel
	echo "${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT_BEFORE%,}"
	sudo ${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT_BEFORE%,}
	sleep 1

	echo "    ${MCMOD_DIR}/bin/mcexec ${USR_PROC}"
	timeout -sKILL 5 ${MCMOD_DIR}/bin/mcexec ${USR_PROC}
	STATUS=$?

	echo "${MCMOD_DIR}/sbin/ihkosctl ${OS_IDX} kmsg"
	sudo ${MCMOD_DIR}/sbin/ihkosctl ${OS_IDX} kmsg

	if [ "$STATUS" -ne 21 ];
	then
		echo ">>> Out-of-range address Test End(Timeout!!!)"
	else
		echo ">>> Out-of-range address Test End"
	fi

	# Out-of-range address Test(After correspondence)
	echo ">>> Out-of-range address(After correspondence) Test Start"

	# stop mckernel
	sudo ${MCMOD_DIR}/sbin/mcstop+release.sh
	sleep 1
	# boot mckernel
	echo "${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT_AFTER%,}"
	sudo ${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT_AFTER%,}
	sleep 1

	echo "    ${MCMOD_DIR}/bin/mcexec ${USR_PROC}"
	timeout -sKILL 5 ${MCMOD_DIR}/bin/mcexec ${USR_PROC}
	STATUS=$?

	echo "${MCMOD_DIR}/sbin/ihkosctl ${OS_IDX} kmsg"
	sudo ${MCMOD_DIR}/sbin/ihkosctl ${OS_IDX} kmsg

	if [ "$STATUS" -ne 21 ];
	then
		echo ">>> Out-of-range address Test End(Timeout!!!)"
	else
		echo ">>> Out-of-range address Test End"
	fi
done

### LTP START ##################################################
# stop mckernel
sudo ${MCMOD_DIR}/sbin/mcstop+release.sh
sleep 1

# boot mckernel
echo "${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT_LTP%,}"
sudo ${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT_LTP%,}
sleep 1

if [ ! -e "/dev/mcos0" ]; then
	echo "Error: failed to mcreboot"
	exit 1
fi


TEST_NUM=`wc -l ${LTP_TESTCASE_FILE} | awk '{print $1}'`
echo ">>> LTP Test Start( $TEST_NUM counts )"

# exec mckernel test program
COUNT=0
while read line
do 
	((COUNT++))
	echo "$COUNT:${MCMOD_DIR}/bin/mcexec ${LTP_DIR}$line"
#	${MCMOD_DIR}/bin/mcexec ${LTP_DIR}$line &>> ${logfile}
	${MCMOD_DIR}/bin/mcexec ${LTP_DIR}$line
done < ${LTP_TESTCASE_FILE}

echo ">>> LTP Test End"
### LTP END ####################################################

