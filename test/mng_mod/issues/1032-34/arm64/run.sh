#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=1

. ../../../../common.sh

result=0
loop_count=100

#######################
## get_rusgae() test ##
#######################

exp_min_utime=(1900000 1900000 1900000)
exp_max_utime=(2100000 2100000 2100000)
exp_min_stime=(1900000 1900000 3900000)
exp_max_stime=(2100000 2100000 4100000)
utime_line=("5p" "5p" "12p")
exp_min_maxrss=(16896 18944 25088)
exp_max_maxrss=(18944 20992 27136)

for tp_num in `seq 0 2`
do
	p_tp_num=`expr ${tp_num} + 1`
	tp_result=0
	for i in `seq -f %03g 1 ${loop_count}`
	do
		output=`${MCEXEC} ${TESTMCK} -s getrusage -n ${tp_num}`
		utime=`echo "${output}" | tac | sed -n ${utime_line[${tp_num}]} | cut -c 12-`
		utime_s=`echo "${utime}" | cut -d ' ' -f 1 | sed -e 's/[^0-9]//g'`
		utime_us=`echo "${utime}" | cut -d ' ' -f 3 | sed -e 's/[^0-9]//g'`
		utime_us=`expr ${utime_s} \* 1000000 + ${utime_us}`
		if [ ${utime_us} -lt ${exp_min_utime[${tp_num}]} \
			-o ${exp_max_utime[${tp_num}]} -lt ${utime_us} ]; then
			tp_result=-1
			echo ""
			echo "ISSUE0${p_tp_num} n=${i}/${loop_count} utime ng."
			echo "${output}"
		fi

		stime=`echo "${output}" | tac | sed -n 4p | cut -c 12-`
		stime_s=`echo "${stime}" | cut -d ' ' -f 1 | sed -e 's/[^0-9]//g'`
		stime_us=`echo "${stime}" | cut -d ' ' -f 3 | sed -e 's/[^0-9]//g'`
		stime_us=`expr ${stime_s} \* 1000000 + ${stime_us}`
		if [ ${stime_us} -lt ${exp_min_stime[${tp_num}]} \
			-o ${exp_max_stime[${tp_num}]} -lt ${stime_us} ]; then
			tp_result=-1
			echo ""
			echo "ISSUE0${p_tp_num} n=${i}/${loop_count} stime ng."
			echo "${output}"
		fi

		maxrss=`echo "${output}" | tac | sed -n 3p | cut -c 13-`
		if [ ${maxrss} -lt ${exp_min_maxrss[${tp_num}]} \
			-o ${exp_max_maxrss[${tp_num}]} -lt ${maxrss} ]; then
			tp_result=-1
			echo ""
			echo "ISSUE0${p_tp_num} n=${i}/${loop_count} maxrss ng."
		fi

		if [ ${tp_result} != 0 ]; then
			echo "${output}"
			break
		fi

		echo -en "ISSUE0${p_tp_num} n=${i}/${loop_count} ok.\r"
	done

	echo ""
	if [ ${tp_result} == 0 ]; then
		echo "ISSUE0${p_tp_num}: OK"
	else
		echo "ISSUE0${p_tp_num}: NG"
		result=-1
	fi
done

./ins_test_driver.sh

for tp_num in `seq -f %03g 001 010`
do
	tp_result=0
	for i in `seq -f %03g 1 ${loop_count}`
	do
		output=`${MCEXEC} ./CT_${tp_num} 2>&1`
		if [ $? != 0 ]; then
			tp_result=-1
			echo ""
			echo "CT_${tp_num} n=${i}/${loop_count} ng."
			echo "${output}"
			break
		fi
		echo -en "CT_${tp_num} n=${i}/${loop_count} ok.\r"
	done

	echo ""
	if [ ${tp_result} == 0 ]; then
		echo "CT_${tp_num}: OK"
	else
		echo "CT_${tp_num}: NG"
		result=-1
	fi
done

./rm_test_driver.sh

exit ${result}
