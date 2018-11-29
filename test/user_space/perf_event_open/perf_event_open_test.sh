#!/bin/sh

# Functions
function reboot() {
	count=`pgrep -c -f 'mcexec '`
	if [ ${count} -gt 0 ]
	then
#		echo "kill process :" ${count}
		pgrep -l -f 'mcexec '
		pgrep -f 'mcexec ' | xargs sudo kill -9
	fi
#	echo -n "mckernel stopping...  "
	sudo ${MCK_DIR}/sbin/mcstop+release.sh
#	echo "done."
	#sleep 1
	echo -n "mckernel reboot ...."
	sudo ${MCK_DIR}/sbin/mcreboot.sh $BOOTPARAM
	echo "done."
}

function ok_out() {
	echo "[OK] ${TEST_PREFIX}`printf %03d ${TEST_NUM}` $1"
	(( TEST_NUM++ ))
	TEST_CODE=`printf %03d ${TEST_NUM}`
}

function ng_out() {
	echo "[NG] ${TEST_PREFIX}`printf %03d ${TEST_NUM}` $1"
	exit 1
}

function ltp_test() {
	TEST_NAME=$1
#LTP programを実行 logを保存
	${MCK_DIR}/bin/mcexec ${LTP}/testcases/bin/${TEST_NAME} >./result/${TEST_NAME}.log

#LTP log 確認
	NUM=`cat ./test_cases/${TEST_NAME}.txt |wc -l`
	for i in `seq 1 ${NUM}`
	do
		G_TEXT=`head -n ${i} ./test_cases/${TEST_NAME}.txt | tail -n 1`
		result=`grep "${G_TEXT}" ./result/${TEST_NAME}.log` 
		#echo ${G_TEXT}
		rc=$?
		if [ ${rc} -eq 0 ]; then
			ok_out "parf_event_open: ${result}"
		else
			ng_out "parf_event_open: result of ${TEST_NAME} ${i} are different."
		fi
	done
}

TEST_NUM=1
TEST_CODE=001
TEST_PREFIX=perf_

ME=`whoami`
source ${HOME}/.mck_test_config

mkdir -p ./result
reboot
#LTP programを実行 logを保存
${MCK_DIR}/bin/mcexec ${LTP}/testcases/bin/perf_event_open01 >./result/perf_event_open01.log

#kmsgを保存
sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >./result/perf_event_open01.kmsg

#kmsgで結果を出力する。
NUM=`cat ./test_cases/perd_event_open01.kmsg.txt |wc -l`
for i in `seq 1 ${NUM}`
do
	G_TEXT=`head -n ${i} ./test_cases/perd_event_open01.kmsg.txt | tail -n 1`
	result=`grep ${G_TEXT} ./result/perf_event_open01.kmsg`
	rc=$?
	if [ ${rc} -eq 0 ]; then
		text=`echo "perf_event_open: the value is over the function mc_perf_event_alloc:"`
		ok_out "${text} ${G_TEXT}"
	else
		ng_out "perf_e nuvent_open: the value is not over the function mc_perf_event_alloc"
	fi
done

#LTP log 確認
ltp_test "perf_event_open01"
