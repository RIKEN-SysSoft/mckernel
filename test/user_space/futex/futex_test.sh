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
	sudo ${MCK_DIR}/sbin/mcreboot.sh $*
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
	sudo ${MCK_DIR}/bin/mcexec ${LTP}/testcases/bin/${TEST_NAME} >./result/${TEST_NAME}.log

#LTP log 確認
	NUM=`cat ./test_cases/${TEST_NAME}.txt |wc -l`
	for i in `seq 1 ${NUM}`
	do
		G_TEXT=`head -n ${i} ./test_cases/${TEST_NAME}.txt | tail -n 1`
		result=`grep "${G_TEXT}" ./result/${TEST_NAME}.log` 
		#echo ${G_TEXT}
		rc=$?
		if [ ${rc} -eq 0 ]; then
			ok_out "futex: ${result}"
		else
			ng_out "futex: result of ${TEST_NAME} ${i} are different."
		fi
	done
}

TEST_PARAM_FILE=$1
TEST_NUM=1
TEST_CODE=001
TEST_PREFIX=futex_

ME=`whoami`
source ${HOME}/.mck_test_config

mkdir -p result

reboot
#LTP programを実行 logを保存
${MCK_DIR}/bin/mcexec ${LTP}/testcases/bin/futex_wait01 >./result/futex_wait01.log

#kmsgを保存
sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >./result/futex_wait01.kmsg

#kmsgで結果を出力する。
#futex-001 アドレスが正しく引き継いでいることを確認

#システムコールの引数のアドレスを取得
sys_addr=`grep "do_futex" ./result/futex_wait01.kmsg |head -n 1 |cut -d "," -f 2`
grep "get_futex_value_locked" ./result/futex_wait01.kmsg | head -n 1 | grep ${sys_addr} >/dev/null
rc=$?
if [ ${rc} -eq 0 ]; then
	text=`echo "futex: The argument address of futex is taken over by get_futex_value_locked."`
	ok_out "${text}" 
else
	ng_out "futex: The argument value of futex does not match the value of get_futex_value_locked argument."
fi

#futex-002 第１引数と第２引数が同じ値であることを確認
uaddr=`grep "get_futex_value_locked" ./result/futex_wait01.kmsg | head -n 1 | sed s/"^.*\*uaddr:\([0-9]*\),.*$"/"\1"/ `
#echo ${uaddr}
uval=`grep "get_futex_value_locked" ./result/futex_wait01.kmsg | head -n 1 | sed s/"^.*uval:\([0-9]*\),.*$"/"\1"/ `
#echo ${uval}
if [ ${uaddr} = ${uval} ]; then
	text=`echo "futex: The first argument of get_futex_value_locked matched the value of the second argument."`
	ok_out "${text}" 
else
	ng_out "futex: The first argument of get_futex_value_locked does not match the value of the second argument."
fi

#LTP test
ltp_test "futex_wait01"
ltp_test "futex_wait02"
ltp_test "futex_wait03"
ltp_test "futex_wait04"
ltp_test "futex_wait_bitset01"
ltp_test "futex_wait_bitset02"
