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

##################
# ulimit -u test #
##################

${MCEXEC} ${TESTMCK} -s kill -n 1 -- -p 6
if [ $? == 0 ]; then
	echo "ulimit -u 0001: OK"
else
	echo "ulimit -u 0001: NG"
	result=-1
fi

proc=`ps -ho pid,comm -U \`whoami\` | wc -l`
proc=$((${proc} - 2))
default_ulimit_u=`ulimit -u`
ulimit -u 9
output=`${MCEXEC} -t $((6 - ${proc})) ${TESTMCK} -s kill -n 1 -- -p 2 2>&1`
if [ $? != 0 ]; then
	echo "${output}" | grep -q "fork() failed."
	if [ $? == 0 ]; then
		echo "ulimit -u 0002: OK"
	else
		echo "${output}"
		echo "ulimit -u 0002: NG, test_mck \"fork() failed\" not found."
		result=-1
	fi
else
	echo "${output}"
	echo "ulimit -u 0002: NG, test_mck succeeded."
	result=-1
fi

exit ${result}
