#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2019 ##

USELTP=0
USEOSTEST=0
MCREBOOT=0
MCSTOP=0
SVEGDB="gdb"

. ../common.sh

vl_set="64 32 16"
default_vl_procfs="/proc/sys/abi/sve_default_vector_length"
core_pattern="/proc/sys/kernel/core_pattern"
ret=0

if [ -e ${default_vl_procfs} ]; then
	orig_vl=`cat ${default_vl_procfs}`
else
	echo "${default_vl_procfs} not found."
	exit -1
fi

orig_corep=`cat ${core_pattern}`
echo "core.host" > ${core_pattern}

for vl in ${vl_set}
do
	echo "Default VL is ${vl} byte test."

	echo ${vl} > ${default_vl_procfs}
	mcstop
	mcreboot
	sleep 1

	# TEST001-014
	for tp_num in `seq 1 14`
	do
		print_num=`printf %03d ${tp_num}`
		result=`${MCEXEC} ./sve_test ${tp_num} 2>&1`
		if [ $? == 0 ]; then
			echo "TEST${print_num}: OK."
		else
			echo "${result}"
			echo "TEST${print_num}: NG."
			ret=-1
		fi
	done

	# TEST015
	stdbuf -i 0 -o 0 -e 0 ${MCEXEC} ./sve_test 15 > ./TEST015.log 2>&1 &
	sleep 1
	kill -STOP `pidof mcexec`
	sleep 1
	kill -CONT `pidof mcexec`
	sleep 1
	kill -KILL `pidof mcexec`

	cat ./TEST015.log | grep -q -e "failed" -e "NG."
	if [ $? == 1 ]; then
		echo "TEST015: OK."
	else
		cat ./TEST015.log
		echo "TEST015: NG."
		ret=-1
	fi
	rm -f ./TEST015.log

	# TEST016-039
	for tp_num in `seq 16 39`
	do
		# TEST018 is abolition
		if [ ${tp_num} == 18 ]; then
			continue
		fi

		print_num=`printf %03d ${tp_num}`
		result=`${MCEXEC} ./sve_test ${tp_num} 2>&1`
		if [ $? == 0 ]; then
			echo "TEST${print_num}: OK."
		else
			echo "${result}"
			echo "TEST${print_num}: NG."
			ret=-1
		fi
	done

	# TEST040
	${MCEXEC} ./sve_test 40 > /dev/null 2>&1
	${SVEGDB} -x ./inf/TEST040.inf ./sve_test ./core > /dev/null 2>&1
	diff ./exp/TEST040_vl${vl}.exp.log ./TEST040.log > /dev/null 2>&1
	if [ $? == 0 ]; then
		echo "TEST040: OK."
		rm -f ./core
		rm -f ./core.host.*
	else
		cat ./TEST040.log
		echo "TEST040: NG."
		ret=-1
	fi
	rm -f ./TEST040.log

	# TEST041
	${MCEXEC} ${SVEGDB} -x ./inf/TEST041.inf ./sve_test > /dev/null 2>&1
	diff ./exp/TEST041_vl${vl}.exp.log ./TEST041.log > /dev/null 2>&1
	if [ $? == 0 ]; then
		echo "TEST041: OK."
	else
		cat ./TEST041.log
		echo "TEST041: NG."
		ret=-1
	fi
	rm -f ./TEST041.log
done

mcstop
echo ${orig_corep} > ${core_pattern}
echo ${orig_vl} > ${default_vl_procfs}

exit ${ret}
