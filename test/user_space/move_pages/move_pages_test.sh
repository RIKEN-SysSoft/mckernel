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
	sudo ${MCK_DIR}/bin/mcexec ${LTP}/testcases/bin/${TEST_NAME} > \
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
			ok_out "move_pages: ${result}"
		else
			ng_out "move_pages: result of ${TEST_NAME} ${i} are different."
		fi
	done
}

TEST_PARAM_FILE=$1
TEST_NUM=1
TEST_CODE=001
TEST_PREFIX=mp_

ME=`whoami`
source ${HOME}/.mck_test_config

mkdir -p ./result

# Don't forget to allocate memory from 2 NUMA nodes 
reboot

ltp_test "move_pages01"

reboot

#LTP programを実行 logを保存
sudo ${MCK_DIR}/bin/mcexec ${LTP}/testcases/bin/move_pages02 > \
	./result/move_pages02.log

#kmsgを保存
sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >./result/move_pages02.kmsg

#move_pages-002 第３引数のアドレスが正しく引き継いでいることを確認
#システムコールの引数のアドレスを取得
sys_virt_addr=`grep "sys_move_pages" ./result/move_pages02.kmsg | head -n 1 | sed -n s/"^.*user_virt_addr:\([0-9a-f]*\),.*$"/"\1"/p `
#echo ${sys_virt_addr}
#実行関数の引数のアドレスを取得
handl_virt_addr=`grep "move_pages_smp_handler" ./result/move_pages02.kmsg | head -n 1 | sed -n s/"^.*user_virt_addr:\([0-9a-f]*\),.*$"/"\1"/p `
#echo ${handl_virt_addr}
if [ ${#sys_virt_addr} -ne 0  -a ${sys_virt_addr} = ${handl_virt_addr} ]; then
	text=`echo "move_pages: The argument address of move_pages is taken over by move_pages_smp_handler"`
	ok_out "${text} user_virt_addr:${sys_virt_addr}" 
else
	ng_out "move_pages: The argument value of process_vm_writev does not match the value of do_process_vm_read_writev argument."
fi

#move_pages-003 第４引数のアドレスが正しく引き継いでいることを確認
#システムコールの引数のアドレスを取得
sys_user_nodes=`grep "sys_move_pages" ./result/move_pages02.kmsg | head -n 1 | sed s/"^.*user_nodes:\([0-9a-f]*\),.*$"/"\1"/ `
#echo ${sys_user_nodes}
#実行関数の引数のアドレスを取得
handl_user_nodes=`grep "move_pages_smp_handler" ./result/move_pages02.kmsg | head -n 1 | sed s/"^.*user_nodes:\([0-9a-f]*\),.*$"/"\1"/ `
#echo ${handl_user_nodes}
if [ ${#sys_user_nodes} -ne 0 -a ${sys_user_nodes} = ${handl_user_nodes} ]; then
	text=`echo "move_pages: The argument address of move_pages is taken over by move_pages_smp_handler"`
	ok_out "${text} user_modes:${sys_user_nodes}" 
else
	ng_out "move_pages: The argument value of process_vm_writev does not match the value of do_process_vm_read_writev argument."
fi

#move_pages-004 第５引数のアドレスが正しく引き継いでいることを確認
#システムコールの引数のアドレスを取得
sys_user_status=`grep "sys_move_pages" ./result/move_pages02.kmsg | head -n 1 | sed s/"^.*user_status:\([0-9a-f]*\).*$"/"\1"/ `
#echo ${sys_user_status}
#実行関数の引数のアドレスを取得
handl_user_status=`grep "move_pages_smp_handler" ./result/move_pages02.kmsg | head -n 1 | sed s/"^.*user_status:\([0-9a-f]*\).*$"/"\1"/ `
#echo ${handl_user_status}
if [ ${#sys_user_status} -ne 0 -a ${sys_user_status} = ${handl_user_status} ]; then
	text=`echo "move_pages: The argument address of move_pages is taken over by move_pages_smp_handler"`
	ok_out "${text} user_modes:${sys_user_status}" 
else
	ng_out "move_pages: The argument value of process_vm_writev does not match the value of do_process_vm_read_writev argument."
fi

ltp_test "move_pages02"

ltp_test "move_pages04"

ltp_test "move_pages06"

ltp_test "move_pages07"

ltp_test "move_pages08"

ltp_test "move_pages09"

ltp_test "move_pages10"
