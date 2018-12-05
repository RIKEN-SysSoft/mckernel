#!/bin/sh
## go_test_McKernal.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=1
USEOSTEST=0
MCREBOOT=0
MCSTOP=0

# read common.sh
. ../../common.sh

LTP_TESTCASE_FILE="./LTP_testcase.txt"
USR_PROC="./memtest_destroy"

#TESTCASES=./testcases_4K/*.txt
TESTCASES=./testcases_64K/*.txt

# mcexec process kill
./utils/kill_mcexec.sh &> /dev/null

for test_case in `ls -1 ${TESTCASES}`
do
	# read testcase param
	source ${test_case}
	case_name=`basename ${test_case} .txt`
	echo "####################"
	echo "Test No:${case_name}"

	# Out-of-range address Test(Before correspondence)
	echo ">>> Out-of-range address Test(Before correspondence) Start"

	# stop mckernel
	mcstop
	sleep 1

	# boot mckernel
	echo "${SBIN}/mcreboot.sh ${MCRBT_OPT_BEFORE%,}"
	sudo ${SBIN}/mcreboot.sh ${MCRBT_OPT_BEFORE%,}
	sleep 1

	echo "    ${MCEXEC} ${USR_PROC}"
	timeout -sKILL 5 ${MCEXEC} ${USR_PROC}
	STATUS=$?

	echo "${IHKOSCTL} 0 kmsg"
	sudo ${IHKOSCTL} 0 kmsg

	if [ "$STATUS" -ne 21 ];
	then
		echo ">>> Out-of-range address Test End(Timeout!!!)"
	else
		echo ">>> Out-of-range address Test End"
	fi

	# Out-of-range address Test(After correspondence)
	echo ">>> Out-of-range address(After correspondence) Test Start"

	# stop mckernel
	mcstop
	sleep 1

	# boot mckernel
	echo "${SBIN}/mcreboot.sh ${MCRBT_OPT_AFTER%,}"
	sudo ${SBIN}/mcreboot.sh ${MCRBT_OPT_AFTER%,}
	sleep 1

	echo "    ${MCEXEC} ${USR_PROC}"
	timeout -sKILL 5 ${MCEXEC} ${USR_PROC}
	STATUS=$?

	echo "${IHKOSCTL} 0 kmsg"
	sudo ${IHKOSCTL} 0 kmsg

	if [ "$STATUS" -ne 21 ];
	then
		echo ">>> Out-of-range address Test End(Timeout!!!)"
	else
		echo ">>> Out-of-range address Test End"
	fi
done

### LTP START ##################################################
# stop mckernel
mcstop
sleep 1

# boot mckernel
mcreboot
sleep 1

if [ ! -e "/dev/mcos0" ]; then
	echo "Error: failed to mcreboot"
	exit 1
fi

TEST_NUM=`wc -l ${LTP_TESTCASE_FILE} | awk '{print $1}'`
echo ">>> LTP Test Start( $TEST_NUM counts )"

# exec mckernel test program

# mktmp for mmapstress04 testcase
TMPFILE=`mktemp /tmp/example.XXXXXXXXXX`
ls -lR /usr/include/ > ${TMPFILE}

COUNT=0
while read line
do
	((COUNT++))
	echo "${COUNT}:${MCEXEC} ${LTPBIN}/${line}"
	if [ ! -e ${LTPBIN}/${line} ]; then
		echo "${LTPBIN}/${line} not found."
		continue
	fi

	if [ "${line}" = "mmapstress04" ]; then
		ARG=${TMPFILE}
	else
		ARG=""
	fi

	${MCEXEC} ${LTPBIN}/${line} ${ARG}
	if [ $? != 0 ]; then
		echo "##### ${line} returned not 0 #####"
	fi
done < ${LTP_TESTCASE_FILE}

rm -f ${TMPFILE}

echo ">>> LTP Test End"
### LTP END ####################################################

