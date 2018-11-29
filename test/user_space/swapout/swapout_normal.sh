#!/bin/sh

# Functions
function reboot() {
	count=`pgrep -c -f 'mcexec '`
	if [ ${count} -gt 0 ]
	then
		echo "kill process :" ${count}
		pgrep -l -f 'mcexec '
		pgrep -f 'mcexec ' | xargs sudo kill -9
	fi
#	echo -n "mckernel stopping...  "
	sudo ${MCK_DIR}/sbin/mcstop+release.sh
#	echo "done."
	#sleep 1
	echo -n "mckernel booting...  " 1>&2
	sudo ${MCK_DIR}/sbin/mcreboot.sh $*
	echo "done." 1>&2
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

TEST_PARAM_FILE=$1
TEST_NUM=23
TEST_CODE=001
TEST_PREFIX=so_

ME=`whoami`

# read config
source ./config

mkdir -p result

reboot 
#programを実行 logを保存
${MCK_DIR}/bin/mcexec ./swaptest 2 >./result/swapout_normal.log

#kmsgを保存
sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >./result/swapout_normal.kmsg

#swapout023 execute swaptest(return code) 
grep "^swapout returns: 0$" ./result/swapout_normal.log
ret=$?
if [ ${ret} -eq 0 ]; then
	ok_out "swaptest program is nomrmal exit." 
else
	ng_out "swaptest pogram is abnormal exit."
fi

#swapout024 execute swaptest (restore data)
grep "^data = hello$" ./result/swapout_normal.log
ret=$?
if [ ${ret} -eq 0 ]; then
	ok_out "confirmed restoration of data." 
else
	ng_out "did not restore the data."
fi

#wapout025 execute swapout (restore user space)
rc=1
for str in `sed -n -e /"^.*: SWAP:.*$"/,/"^.*: MLOCK:.*$"/p ./result/swapout_normal.kmsg |sed -n s/"^\[  0\]: \t\([0-9a-f]*\) -- \([0-9a-f]*\)$"/"\1:\2"/p`
do
	grep ${str} ./result/swapout_normal.kmsg >/dev/null
	rtn=$?
	if [ ${rtn} -eq 0 ]; then
		echo ${str} is matched.
		rc=0
	else
		echo ${str} is not matched.
		rc=1
		break
	fi
done
if [ ${rc} -eq 0 ]; then
	ok_out "pageout areas and pagein areas are matched."
else
	ng_out "pagein areas is not matched."
fi
