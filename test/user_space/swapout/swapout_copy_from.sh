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
	sudo ${MCK_DIR}/sbin/mcreboot.sh $BOOTPARAM
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
TEST_NUM=1
TEST_CODE=001
TEST_PREFIX=so_

ME=`whoami`

# read config
source ./config

mkdir -p ./result

reboot 
make

#programを実行 logを保存
${MCK_DIR}/bin/mcexec ./swaptest 2 >./result/swapout_copy_from.log

#kmsgを保存
sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >./result/swapout_copy_from.kmsg

#swapout001 arealist_update i and count check.
#arealist_update i 
arealist_i=`grep "arealist_update" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user i:\([0-9a-f]*\),.*$"/"\1"/ `
#echo ${arearlist_i}
#arealist_update count
arealist_count=`grep "arealist_update" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*count:\([0-9a-f]*\).*$"/"\1"/ `
#echo ${arearlist_count}
if [ ${#arealist_i} -ne 0 -a ${arealist_i} = ${arealist_count} ]; then
	text=`echo "arealist_update:variable i matched rea->tail->count"`
	ok_out "${text} :(${arealist_i})" 
else
	ng_out "arealist_update: The value of count does not match the value of i."
fi

#swapout002 mlocklist_morereq went.count and ent->count check.
#ent.count
went=`grep "mlocklist_morereq" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user went.count:\([0-9a-f]*\),.*$"/"\1"/ `
#echo ${went}
#ent->count
ent=`grep "mlocklist_morereq" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*->count:\([0-9a-f]*\).*$"/"\1"/ `
#echo ${ent}
if [ ${#went} -ne 0 -a ${went} = ${ent} ]; then
	text=`echo "mlocklist_morereq:variable ent.count matched ent->count"`
	ok_out "${text} :(${went})" 
else
	ng_out "mlocklist_morereq: The value of count does not match the value of i."
fi

#swapout003 arealist_preparewrite went.count and ent->count check.
#ent.count
went=`grep "arealist_preparewrite" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user went.count:\([0-9a-f]*\),.*$"/"\1"/ `
#echo ${went}
ent=`grep "arealist_preparewrite" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*->count:\([0-9a-f]*\).*$"/"\1"/ `
#echo ${ent}
if [ ${#went} -ne 0 -a ${went} = ${ent} ]; then
	text=`echo "arealist_preprarewrite:variable ent.count matched ent->count"`
	ok_out "${text} :(${went})" 
else
	ng_out "arealist_preprarewrite: The value of count does not match the value of i."
fi

#swapout004 do_pageout loop1 si->swap_info[].start and sw_info.start check.
#swap_inf
swap_info=`grep "do_pageout:1" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user \([0-9|a-f]*\):.*$"/"\1"/ `
#echo ${swap_info}
#sw_info
sw_info=`grep "do_pageout:1" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user [0-9|a-f]*:\([0-9|a-f]*\).*$"/"\1"/ `
#echo ${sw_info}
if [ ${#swap_info} -ne 0 -a ${swap_info} = ${sw_info} ]; then
	text=`echo "do_pageout loop1:variable swap_info[].start matched sw_info.start"`
	ok_out "${text} :(${swap_info})" 
else
	ng_out "do_pageout loop1: The value of swapinfo[].start does not match the value of sw_info.start."
fi

#swapout005 do_pageout loop2 si->swap_info[].start and sw_info.start check.
swap_info=`grep "do_pageout:2" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user \([0-9|a-f]*\):.*$"/"\1"/ `
#echo ${swap_info}
sw_info=`grep "do_pageout:2" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user [0-9|a-f]*:\([0-9|a-f]*\).*$"/"\1"/ `
#echo ${sw_info}
if [ ${#swap_info} -ne 0 -a ${swap_info} = ${sw_info} ]; then
	text=`echo "do_pageout loop2:variable swap_info[].start matched sw_info.start"`
	ok_out "${text} :(${swap_info})" 
else
	ng_out "do_pageout loop2: The value of swapinfo[].start does not match the value of sw_info.start."
fi

#swapout006 do_pageout loop3 si->swap_info[].start and sw_info.start check.
#swap_inf
swap_info=`grep "do_pageout:3" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user \([0-9|a-f]*\):.*$"/"\1"/ `
#echo ${swap_info}
sw_info=`grep "do_pageout:3" ./result/swapout_copy_from.kmsg | head -n 1 | sed s/"^.*copy_from_user [0-9|a-f]*:\([0-9|a-f]*\).*$"/"\1"/ `
#echo ${sw_info}
if [ ${#swap_info} -ne 0 -a ${swap_info} = ${sw_info} ]; then
	text=`echo "do_pageout loop3:variable swap_info[].start matched sw_info.start"`
	ok_out "${text} :(${swap_info})" 
else
	ng_out "do_pageout loop3: The value of swapinfo[].start does not match the value of sw_info.start."
fi

