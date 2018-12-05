#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=1
USEOSTEST=1

. ../../common.sh

result=0

###########################
# Issue727 test(no-patch) #
###########################

${MCEXEC} ./exec
if [ $? == 0 ]; then
	echo "Issue727_0001: OK"
else
	echo "Issue727_0001: NG"
	result=-1
fi

##################
# Issue 873 test #
##################

isseu873_result=0
REP_NUM=100
for i in `seq -f %03g 1 ${REP_NUM}`
do
	sudo "${SBIN}/mcstop+release.sh"
	sleep 1
	sudo "${SBIN}/mcreboot.sh" ${BOOTPARAM}

	if [ $? != 0 ]; then
		echo ""
		echo "[NG] failed to boot Mckernel  :${i}"
		isseu873_result=-1
		break
	fi
	echo -en "Issue873_0001 n=${i}/${REP_NUM} ok.\r"
done
echo ""

if [ ${isseu873_result} == 0 ]; then
	echo "[OK] succeed to boot McKernel ${i} times"
	echo "Issue873_0001: OK"
else
	echo "Issue873_0001: NG"
	result=-1
fi

#############################
# Issue 1011 test(no-patch) #
#############################

${MCEXEC} hostname
if [ $? == 0 ]; then
	echo "Issue1011_0001: OK"
else
	echo "Issue1011_0001: NG"
	result=-1
fi

##################
# ulimit -u test #
##################

nprocs=`ps -ho pid,comm -U `whoami` | wc -l`

${MCEXEC} -t $((8 - nprocs)) ${TESTMCK} -s kill -n 1 -- -p 6
if [ $? == 0 ]; then
	echo "ulimit -u 0001: OK"
else
	echo "ulimit -u 0001: NG"
	result=-1
fi

ulimit -u 9
${MCEXEC} -t $((8 - nprocs)) ${TESTMCK} -s kill -n 1 -- -p 6
if [ $? != 0 ]; then
	echo "ulimit -u 0002: OK"
else
	echo "ulimit -u 0002: NG"
	result=-1
fi

#######################
# LTP regression test #
#######################

export PATH=${LTPBIN}:${PATH}
while read line
do
	tp=`echo ${line} | cut -d ' ' -f 1`

	if [ ! -e ${LTPBIN}/${tp} ]; then
		echo "${LTPBIN}/${tp} not found."
		continue
	fi

	timeout -sKILL 5m ${MCEXEC} ${LTPBIN}/${line}
	if [ $? != 0 ]; then
		echo "##### ${tp} returned not 0 #####"
		result=-1
	fi
done < ./ltplist.txt

exit ${result}
