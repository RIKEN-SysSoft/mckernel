#!/bin/sh
## run_allow_oversubscribe.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../common.sh

. ./config

result=0

####################
## -O option test ##
####################

${MCEXEC} ./allow_oversubscribe 4
if [ `echo $?` != 0 ]; then
	echo "TEST021: OK"
else
	echo "TEST021: NG, not -O setting mcexec."
	result=-1
fi

BOOTPARAM="${BOOTPARAM} -O"
((${MCSTOP-1})) && mcstop
((${MCREBOOT-1})) && mcreboot

${MCEXEC} ./allow_oversubscribe 4
if [ `echo $?` == 0 ]; then
	echo "TEST022: OK"
else
	echo "TEST022: NG, -O setting mcexec."
	result=-1
fi

exit ${result}
