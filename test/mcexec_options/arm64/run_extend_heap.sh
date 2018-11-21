#!/bin/sh
## run_extend_heap.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../common.sh

. ./config

result=0

####################
## -h option test ##
####################

${MCEXEC} -h ${NEAR_PGSZ_LOW} ./extend_heap ${NEAR_PGSZ_LOW_VAL}
if [ `echo $?` == 0 ]; then
	echo "TEST001: OK"
else
	echo "TEST001: NG, -h ${NEAR_PGSZ_LOW} options failed."
	result=-1
fi

${MCEXEC} -h ${NEAR_LPGSZ_LOW} ./extend_heap ${NEAR_LPGSZ_LOW_VAL}
if [ `echo $?` == 0 ]; then
	echo "TEST002: OK"
else
	echo "TEST002: NG, -h ${NEAR_LPGSZ_LOW} options failed."
	result=-1
fi

${MCEXEC} -h 1G ./extend_heap $((1024*1024*1024))
if [ `echo $?` == 0 ]; then
	echo "TEST003: OK"
else
	echo "TEST003: NG, -h 1G options failed."
	result=-1
fi

${MCEXEC} -h ${NEAR_PGSZ_HIGH} ./extend_heap ${NEAR_PGSZ_HIGH_VAL}
if [ `echo $?` == 0 ]; then
	echo "TEST004: OK"
else
	echo "TEST004: NG, -h ${NEAR_PGSZ_HIGH} options failed."
	result=-1
fi

${MCEXEC} -h ${NEAR_LPGSZ_HIGH} ./extend_heap ${NEAR_LPGSZ_HIGH_VAL}
if [ `echo $?` == 0 ]; then
	echo "TEST005: OK"
else
	echo "TEST005: NG, -h ${NEAR_LPGSZ_HIGH} options failed."
	result=-1
fi

${MCEXEC} -h 2g ./extend_heap $((2*1024*1024*1024))
if [ `echo $?` == 0 ]; then
	echo "TEST006: OK"
else
	echo "TEST006: NG, -h 2g options failed."
	result=-1
fi

${MCEXEC} -h ${PGSZ} ./extend_heap ${PGSZ}
if [ `echo $?` == 0 ]; then
	echo "TEST007: OK"
else
	echo "TEST007: NG, -h ${PGSZ} options failed."
	result=-1
fi

${MCEXEC} -h ${LPGSZ} ./extend_heap ${LPGSZ}
if [ `echo $?` == 0 ]; then
	echo "TEST008: OK"
else
	echo "TEST008: NG, -h ${LPGSZ} options failed."
	result=-1
fi

exit ${result}
