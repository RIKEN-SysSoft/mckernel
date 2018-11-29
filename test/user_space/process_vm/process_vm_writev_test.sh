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
	if [ $# -eq 1 ]; then
		TP_NAME=${TEST_NAME}
	else
		TP_NAME=$2
	fi
#LTP programを実行 logを保存
	sudo ${MCK_DIR}/bin/mcexec ${LTP}/testcases/bin/${TP_NAME} > \
		./result/${TEST_NAME}.log

#LTP log 確認
	NUM=`cat ./test_cases/${TEST_NAME}.txt |wc -l`
	for i in `seq 1 ${NUM}`
	do
		G_TEXT=`head -n ${i} ./test_cases/${TEST_NAME}.txt | tail -n 1`
		result=`grep "${G_TEXT}" ./result/${TEST_NAME}.log` 
		#echo ${G_TEXT}
		rc=$?
		if [ ${rc} -eq 0 ]; then
			ok_out "process_vm_writev: ${result}"
		else
			ng_out "process_vm_writev: result of ${TEST_NAME} ${i} are different."
		fi
	done
}

TEST_PARAM_FILE=$1
TEST_NUM=1
TEST_CODE=001
TEST_PREFIX=pvw_

ME=`whoami`
source ${HOME}/.mck_test_config

mkdir -p ./result

reboot
#LTP programを実行 logを保存
sudo ${MCK_DIR}/bin/mcexec ${LTP}/testcases/bin/process_vm01 -w > \
	./result/process_vm_writev01.log

#kmsgを保存
sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >./result/process_vm_writev01.kmsg

#process_vm_writev-001 第２引数のアドレスが正しく引き継いでいることを確認
#システムコールの引数のアドレスを取得
sys_arg2_addr=`grep "sys_process_vm_writev" ./result/process_vm_writev01.kmsg | head -n 1 | sed s/"^.*arg2_addr:\([0-9|a-f]*\),.*$"/"\1"/ `
#echo ${sys_arg2_addr}
#実行関数の引数のアドレスを取得
do_arg2_addr=`grep "do_process_vm_read_writev" ./result/process_vm_writev01.kmsg | head -n 1 | sed s/"^.*arg2_addr:\([0-9|a-f]*\),.*$"/"\1"/ `
#echo ${do_arg2_addr}
if [ ${#sys_arg2_addr} -ne 0 -a ${sys_arg2_addr} = ${do_arg2_addr} ]; then
	text=`echo "process_vm_writev: The argument address of process_vm_writev is taken over by do_process_vm_read_writev"`
	ok_out "${text} arg2:${sys_arg2_addr}" 
else
	ng_out "process_vm_writev: The argument value of process_vm_writev does not match the value of do_process_vm_read_writev argument."
fi

#process_vm_writev-001 第４引数のアドレスが正しく引き継いでいることを確認
#システムコールの引数のアドレスを取得
sys_arg4_addr=`grep "sys_process_vm_writev" ./result/process_vm_writev01.kmsg | head -n 1 | sed s/"^.*arg4_addr:\([0-9|a-f]*\).*$"/"\1"/ `
#echo ${sys_arg4_addr}
#実行関数の引数のアドレスを取得
do_arg4_addr=`grep "do_process_vm_read_writev" ./result/process_vm_writev01.kmsg | head -n 1 | sed s/"^.*arg4_addr:\([0-9|a-f]*\).*$"/"\1"/ `
#echo ${do_arg4_addr}
if [ ${#sys_arg4_addr} -ne 0 -a ${sys_arg4_addr} = ${do_arg4_addr} ]; then
	text=`echo "process_vm_writev: The argument address of process_vm_writev is taken over by do_process_vm_read_writev"`
	ok_out "${text} arg4:${sys_arg4_addr}" 
else
	ng_out "process_vm_writev: The argument value of process_vm_writev does not match the value of do_process_vm_read_writev argument."
fi

ltp_test "process_vm_writev01" "process_vm01 -w"
ltp_test "process_vm_writev02"
