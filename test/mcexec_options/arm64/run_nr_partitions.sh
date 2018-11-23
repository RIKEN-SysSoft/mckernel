#!/bin/sh
## run_nr_partitions.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../common.sh

. ./config

result=0

####################
## -n option test ##
####################

${MCEXEC} -n 2 ls > /dev/null &
sleep 1
${MCEXEC} -n 2 ls > /dev/null
if [ `echo $?` == 0 ]; then
	echo "TEST017: OK"
else
	echo "TEST017: NG, -n 2 setting."
	result=-1
fi

${MCEXEC} -n 4 ls > /dev/null &
sleep 1
${MCEXEC} -n 4 ls > /dev/null &
sleep 1
${MCEXEC} -n 4 ls > /dev/null &
sleep 1
${MCEXEC} -n 4 ls > /dev/null
if [ `echo $?` == 0 ]; then
	echo "TEST018: OK"
else
	echo "TEST018: NG, -n 4 setting."
	result=-1
fi

${MCEXEC} -n 8 ls
if [ `echo $?` != 0 ]; then
	echo "TEST019: OK"
else
	echo "TEST019: NG, -n <over mckcores> setting."
	result=-1
fi

${MCEXEC} -n abcde ls
if [ `echo $?` != 0 ]; then
	echo "TEST020: OK"
else
	echo "TEST020: NG, -n <invalid strings> setting."
	result=-1
fi

exit ${result}
