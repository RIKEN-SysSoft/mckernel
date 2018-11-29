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
TEST_NUM=7
TEST_CODE=001
TEST_PREFIX=so_

ME=`whoami`

# read config
source ./config

mkdir -p result

reboot 
#programを実行 logを保存
${MCK_DIR}/bin/mcexec ./swaptest 2 >./result/swapout_copy_to_01.log

#kmsgを保存
sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >./result/swapout_copy_to_01.kmsg

#swapout007 arealist_update i and count check.
arealist_i=`grep "arealist_update" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*copy_to_user i:\([0-9a-f]*\),.*$"/"\1"/ `
#echo ${arearlist_i}
arealist_count=`grep "arealist_update" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*count:\([0-9a-f]*\).*$"/"\1"/ `
#echo ${arearlist_count}
if [ ${#arealist_i} -ne 0 -a ${arealist_i} = ${arealist_count} ]; then
	text=`echo "arealist_update:variable i matched rea->tail->count"`
	ok_out "${text} :(${arealist_i})" 
else
	ng_out "arealist_update: The value of count does not match the value of i."
fi

#swapout008 arealist_add addr->start and waddr.start check.
addr=`grep "arealist_add" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*copy_to_user addr->start:\([0-9a-f]*\),.*$"/"\1"/ `
#echo ${addr}
waddr=`grep "arealist_add" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*waddr.start:\([0-9a-f]*\)$"/"\1"/ `
#echo ${waddr}
if [ ${#addr} -ne 0 -a ${addr} = ${waddr} ]; then
	text=`echo "arealist_add:addr->start matched waddr.start"`
	ok_out "${text} :(${waddr})" 
else
	ng_out "arealist_add: The value of addr->start does not match the value of wsddr.start."
fi

#swapout009 do_pageout si->swapfname and si->udata_buf check.
udata_buf=`grep "do_pageout" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*copy_to_user si->udata_buf:\(.*\),.*$"/"\1"/ `
#echo ${udata_buf}
swapfname=`grep "do_pageout" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*si->swapfname:\(.*\)$"/"\1"/ `
#echo ${swapfname}
if [ ${#udata_buf} -ne 0 -a "${udata_buf}" = "${swapfname}" ]; then
	text=`echo "do_pageout:variable si->udata_buf matched si->swapfname"`
	ok_out "${text} :(${udata_buf})" 
else
	ng_out "do_pageout: The value of si->udata_buf does not match the value of si->swapfname."
fi

#swapout010 do_pageout si->swphdr->magic
magic=`grep "do_pageout:.* si->swphdr->magic" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*copy_to_user si->swphdr->magic:\(.*\),si->swphdr->version:.*$"/"\1"/ `
#echo ${magic}
if [ "${magic}" = "McKernel swap" ]; then
	text=`echo "do_pageout:si->swphdr->magic is McKernel swap"`
	ok_out "${text} :(${magic})" 
else
	ng_out "do_pageout: does not match the value of si->swphdr->magic."
fi

#swapout011 do_pageout si->swphdr->version
version=`grep "do_pageout:.*,si->swphdr->version" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*copy_to_user .*,si->swphdr->version:\(.*\),si->swphdr->count_sarea:.*$"/"\1"/ `
#echo ${version}
if [ "${version}" = "${MCKERNEL_VERSION}" ]; then
	text=`echo "do_pageout:si->swphdr->version is ${MCKERNEL_VERSION}"`
	ok_out "${text} :(${version})" 
else
	ng_out "do_pageout: does not match the value of si->swphdr->version."
fi

#swapout012 d_pageout si->swphdr->count_sarea
sarea=`grep "do_pageout:.*,si->swphdr->count_sarea" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*copy_to_user .*,si->swphdr->count_sarea:\([0-9|a-f]*\),.*$"/"\1"/ `
echo ${sarea}
count=`grep "do_pageout:.*,si->swphdr->count_sarea" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*si->swap_area.count:\([0-9|a-f]*\),.*$"/"\1"/ `
#echo ${count}
if [ ${#sarea} -ne 0 -a ${sarea} = ${count} ]; then
	text=`echo "do_pageout:variable count_sarea matched swap_area.count"`
	ok_out "${text} :(${sarea})" 
else
	ng_out "do_pageout: The value of count_sarea does not match the value of swap_area.count."
fi

#swapout013 d_pageout si->swphdr->count_marea
marea=`grep "do_pageout:.*si->swphdr->count_marea" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*copy_to_user .*,si->swphdr->count_marea:\([0-9|a-f]*\),.*$"/"\1"/ `
#echo ${marea}
count=`grep "do_pageout:.*si->mlock_area.count" ./result/swapout_copy_to_01.kmsg | head -n 1 | sed s/"^.*si->mlock_area.count:\([0-9|a-f]*\)$"/"\1"/ `
#echo ${count}
if [ ${#marea} -ne 0 -a ${marea} = ${count} ]; then
	text=`echo "do_pageout:variable count_marea matched mlock_area.count"`
	ok_out "${text} :(${marea})" 
else
	ng_out "do_pageout: The value of count_marea does not match the value of mlock_area.count."
fi
