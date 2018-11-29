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
TEST_NUM=14
TEST_CODE=001
TEST_PREFIX=so_

ME=`whoami`

# read config
source ./config

mkdir -p ./result

reboot 
#programを実行 logを保存
${MCK_DIR}/bin/mcexec ./swaptest 2 >./result/swapout_copy_to_02.log

#kmsgを保存
sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >./result/swapout_copy_to_02.kmsg

#swapout014 arealist_preparewrite info[].start
start=`grep "arealist_preparewrite:.* info\[[0-9]\].start:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.*copy_to_user info\[[0-9]\].start:\([0-9|a-f]*\),end:.*$"/"\1"/ `
#echo ${start}
wstart=`grep "arealist_preparewrite:.* ,went.pair\[[0-9]\]\.start:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* ,went.pair\[[0-9]\]\.start:\([0-9|a-f]*\),end:.*$"/"\1"/ `
#echo ${wstart}
if [ ${#start} -ne 0 -a "${start}" = "${wstart}" ]; then
	text=`echo "arealist_preparewrite:info[].start matched went.pair[].start"`
	ok_out "${text} :(${start})" 
else
	ng_out "arealist_preparewrite: does not match the value of info[].start"
fi

#swapout015 arealist_preparewrite info[].end
end=`grep "arealist_preparewrite:.* info\[[0-9]\].start:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.*copy_to_user info\[[0-9]\].start:[0-9|a-f]*,end:\([0-9|a-f]*\),flag:.*$"/"\1"/ `
#echo ${end}
wend=`grep "arealist_preparewrite:.* ,went.pair\[[0-9]\]\.start:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* ,went.pair\[[0-9]\].start:[0-9|a-f]*,end:\([0-9|a-f]*\),flag:.*$"/"\1"/ `
#echo ${wend}
if [ ${#end} -ne 0 -a "${end}" = "${wend}" ]; then
	text=`echo "arealist_preparewrite:info[].end matched went.pair[].end"`
	ok_out "${text} :(${end})" 
else
	ng_out "arealist_preparewrite: does not match the value of info[].end"
fi

#swapout016 arealist_preparewrite info[].flag
flag=`grep "arealist_preparewrite:.* info\[[0-9]\].start:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.*copy_to_user info\[[0-9]\].start:[0-9a-f]*,.*flag:\([0-9a-f]*\) ,.*$"/"\1"/ `
#echo ${flag}
wflag=`grep "arealist_preparewrite:.* ,went.pair\[[0-9]\]\.start:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* ,went.pair\[[0-9]\].start:[0-9a-f]*,.*flag:\([0-9a-f]*\)$"/"\1"/ `
#echo ${wflag}
if [ ${#flag} -ne 0 -a "${flag}" = "${wflag}" ]; then
	text=`echo "arealist_preparewrite:info[].flag matched went.pair[].flag"`
	ok_out "${text} :(${flag})" 
else
	ng_out "arealist_preparewrite: does not match the value of info[].flag"
fi

#swapout017 arealist_preparewrite info[].pos
pos=`grep "arealist_preparewrite:.* info\[[0-9]\].pos:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.*copy_to_user info\[[0-9]\].pos:\([0-9a-f]*\),pos:[0-9a-f]*$"/"\1"/ `
#echo ${pos}
wpos=`grep "arealist_preparewrite:.* info\[[0-9]\].pos:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.*copy_to_user info\[[0-9]\].pos:[0-9a-f]*,pos:\([0-9a-f]*\)$"/"\1"/ `
#echo ${wpos}
if [ ${#pos} -ne 0 -a  "${pos}" = "${wpos}" ]; then
	text=`echo "arealist_preparewrite:info[].pos matched went.pair[].pos"`
	ok_out "${text} :(${pos})" 
else
	ng_out "arealist_preparewrite: does not match the value of info[].pos"
fi

#swapout018 pager_open swapfname
fname=`grep "pager_open: copy_to_user si->udata_buf:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* si->udata_buf:\(.*\),fname:.*$"/"\1"/ `
#echo ${fname}
wfname=`grep "pager_open: copy_to_user si->udata_buf:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* si->udata_buf:.*,fname:\(.*\)$"/"\1"/ `
#echo ${wfname}
if [ ${#fname} -ne 0 -a "${fname}" = "${wfname}" ]; then
	text=`echo "pager_open:swapfname matched si-udate_buf"`
	ok_out "${text} :(${fname})" 
else
	ng_out "pager_open: does not match the value of swapfname"
fi

#swapout019 pager_unlink swapfname
fname=`grep "pager_unlink: copy_to_user si->udata_buf:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* si->udata_buf:\(.*\),fname:.*$"/"\1"/ `
#echo ${fname}
wfname=`grep "pager_unlink: copy_to_user si->udata_buf:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* si->udata_buf:.*,fname:\(.*\)$"/"\1"/ `
#echo ${wfname}
if [ ${#fname} -ne 0 -a "${fname}" = "${wfname}" ]; then
	text=`echo "pager_unlink:swapfname matched si-udate_buf"`
	ok_out "${text} :(${fname})" 
else
	ng_out "pager_unlink: does not match the value of swapfname"
fi

#swapout020 arealist_get user_space initialize
count=`grep "arealist_get:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.*tmp->count:\([0-9]\) area.*$"/"\1"/ `
#echo ${count}
if [ "${count}" = "0" ]; then
	text=`echo "arealist_get:arealist is inistialized."`
	ok_out "${text} :(${count})" 
else
	ng_out "arealist_get: arealist was not initialized"
fi

#swapout021 prealist_get arealist->next
next=`grep "arealist_get: copy_to_user" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* area->tail->next \([0-9a-f]*\):\([0-9a-f]*\)$"/"\1"/ `
#echo ${next}
wnext=`grep "arealist_get: copy_to_user" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.* area->tail->next \([0-9a-f]*\):\([0-9a-f]*\)$"/"\2"/ `
#echo ${wnext}
if [ ${#next} -ne 0 -a  "${next}" = "${wnext}" ]; then
	text=`echo "arealist_get: area->tail->next is matched"`
	ok_out "${text} :(${next})" 
else
	ng_out "arealist_get: does not match the value of area->tail->next"
fi

#swapout022 arealist_alloc user_space initialize
count=`grep "arealist_alloc:" ./result/swapout_copy_to_02.kmsg | head -n 1 | sed s/"^.*areap->head->count:\([0-9]\)$"/"\1"/ `
#echo ${count}
if [ "${count}" = "0" ]; then
	text=`echo "arealist_alloc:arealist is inistialized."`
	ok_out "${text} :(${count})" 
else
	ng_out "arealist_get: arealist was not initialized"
fi

