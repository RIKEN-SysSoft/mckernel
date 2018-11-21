#!/bin/sh
## run_node_bind.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../common.sh

. ./config

result=0

####################
## -m option test ##
####################

${MCEXEC} -m 1 ./node_bind 1
if [ `echo $?` == 0 ]; then
	echo "TEST009: OK"
else
	echo "TEST009: NG, -m 1 setting."
	result=-1
fi

${MCEXEC} -m 3 ./node_bind 3
if [ `echo $?` == 0 ]; then
	echo "TEST010: OK"
else
	echo "TEST010: NG, -m out of McKernel node setting."
	result=-1
fi

${MCEXEC} -m 0-2 ./node_bind 0-2
if [ `echo $?` == 0 ]; then
	echo "TEST011: OK"
else
	echo "TEST011: NG, -m 0-2 setting."
	result=-1
fi

${MCEXEC} -m 0,2 ./node_bind 0,2
if [ `echo $?` == 0 ]; then
	echo "TEST012: OK"
else
	echo "TEST012: NG, -m 0,2 setting."
	result=-1
fi

${MCEXEC} -m \!0,1,2 ./node_bind \!0,1,2
if [ `echo $?` == 0 ]; then
	echo "TEST013: OK"
else
	echo "TEST013: NG, -m \!0,1,2 setting."
	result=-1
fi

${MCEXEC} -m +0,1 ./node_bind +0,1
if [ `echo $?` == 0 ]; then
	echo "TEST014: OK"
else
	echo "TEST014: NG, -m +0,1 setting."
	result=-1
fi

${MCEXEC} -m all ./node_bind all
if [ `echo $?` == 0 ]; then
	echo "TEST015: OK"
else
	echo "TEST015: NG, -m all setting."
	result=-1
fi

${MCEXEC} -m 63 ./node_bind 63
if [ `echo $?` == 0 ]; then
	echo "TEST016: OK"
else
	echo "TEST016: NG, -m 63 setting."
	result=-1
fi

exit ${result}
