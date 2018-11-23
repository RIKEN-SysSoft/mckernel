#!/bin/sh
## run_stack_premap.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../common.sh

. ./config

result=0

####################################
## -s(--stack-premap) option test ##
####################################

${MCEXEC} -s ${NEAR_PGSZ_LOW},${LPGSZ} ./stack_premap ${NEAR_PGSZ_LOW_VAL}
if [ `echo $?` == 0 ]; then
	echo "TEST023: OK"
else
	echo "TEST023: NG, -s ${NEAR_PGSZ_LOW},${LPGSZ} setting."
	result=-1
fi

${MCEXEC} -s ${NEAR_LPGSZ_LOW},${LPGSZ} ./stack_premap ${NEAR_LPGSZ_LOW_VAL}
if [ `echo $?` == 0 ]; then
	echo "TEST024: OK"
else
	echo "TEST024: NG, -s ${NEAR_LPGSZ_LOW},${LPGSZ} setting."
	result=-1
fi

${MCEXEC} -s 1G,2G ./stack_premap $((1024*1024*1024))
if [ `echo $?` == 0 ]; then
	echo "TEST025: OK"
else
	echo "TEST025: NG, -s 1G,2G setting."
	result=-1
fi

${MCEXEC} --stack-premap ${NEAR_PGSZ_HIGH},${LPGSZ} ./stack_premap ${NEAR_PGSZ_HIGH_VAL}
if [ `echo $?` == 0 ]; then
	echo "TEST026: OK"
else
	echo "TEST026: NG, -s ${NEAR_PGSZ_HIGH},${LPGSZ} setting."
	result=-1
fi

${MCEXEC} --stack-premap ${NEAR_LPGSZ_HIGH},2g ./stack_premap ${NEAR_LPGSZ_HIGH_VAL}
if [ `echo $?` == 0 ]; then
	echo "TEST027: OK"
else
	echo "TEST027: NG, -s ${NEAR_LPGSZ_HIGH},2g setting."
	result=-1
fi

${MCEXEC} --stack-premap 2g,3g ./stack_premap $((2*1024*1024*1024))
if [ `echo $?` == 0 ]; then
	echo "TEST028: OK"
else
	echo "TEST028: NG, -s 2g,3g setting."
	result=-1
fi

${MCEXEC} -s ${PGSZ},${LPGSZ} ./stack_premap ${PGSZ}
if [ `echo $?` == 0 ]; then
	echo "TEST029: OK"
else
	echo "TEST029: NG, -s ${PGSZ},${LPGSZ} setting."
	result=-1
fi

${MCEXEC} --stack-premap ${LPGSZ},${PGSZ} ./stack_premap ${PGSZ}
if [ `echo $?` == 0 ]; then
	echo "TEST030: OK"
else
	echo "TEST030: NG, -s ${LPGSZ},${PGSZ} setting."
	result=-1
fi

exit ${result}
