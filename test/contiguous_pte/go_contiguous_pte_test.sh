#!/bin/sh
# go_contiguous_pte_test.sh COPYRIGHT FUJITSU LIMITED 2018
contiguous_pte_test_dir=$(dirname "${BASH_SOURCE[0]}")

# read config
. ${contiguous_pte_test_dir}/../common.sh
. ${HOME}/.mck_test_config

os_num=0
if [ ! -e "/dev/mcos${os_num}" ]; then
	echo "Error: failed to mcreboot"
	exit 1
fi

logdir="${contiguous_pte_test_dir}/result"
mkdir -p "$logdir"

# exec test program
user_proc="${contiguous_pte_test_dir}/bin/test_contiguous_pte"

for test_case in `grep -E '^TEST_CASE_DEF' ${contiguous_pte_test_dir}/src/test_case.list`
do
	tp_num=`echo $test_case | sed 's|TEST_CASE_DEF(contiguous_pte,||g' | sed 's|)$||g'`
	logfile="${logdir}/${tp_num}.log"

	# check if it can be executed
	timeout 10 ${MCEXEC} ${os_num} ${user_proc} -n null >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		# restart if it can not be executed
		mcstop
		mcreboot
	fi

	# run
	echo "${MCEXEC} ${os_num} ${user_proc} -n $tp_num" >${logfile} 2>&1
	timeout 20 ${MCEXEC} ${os_num} ${user_proc} -n $tp_num >>${logfile}
	rcode=$?

	# check result
	grep -q "^RESULT: ok$" ${logfile}
	if [ $? -eq 0 -a $rcode -eq 0 ]; then
		echo "OK: ${tp_num}"
	else
		echo "NG: ${tp_num}"
		echo "==" >>${logfile}
		echo "${IHKOSCTL} ${os_num} kmsg" >>${logfile}
		sudo ${IHKOSCTL} ${os_num} kmsg >>${logfile}
	fi
done
mcstop
