#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=1
MCREBOOT=0

. ../../common.sh

MCSTAT="${BIN}/mcstat"
BOOTPARAM="-c 4-7 -m 512M@0"

mcreboot

sleep 1

${MCEXEC} ${TESTMCK} -s mem_limits -n 0 -- -s $((64*1024*1024)) -c 1 -f mmap > /dev/null 2>&1

sleep 1

result=0

#################
## mcstat test ##
#################

output=`${MCSTAT} | sed -n -e 3p`
mck_mem_total=$(awk '{print $1}' <<< ${output})
mem_current=$(awk '{print $2}' <<< ${output})
mem_max=$(awk '{print $3}' <<< ${output})
tsc_system=$(awk '{print $4}' <<< ${output})
tsc_user=$(awk '{print $5}' <<< ${output})
thread_current=$(awk '{print $6}' <<< ${output})
thread_max=$(awk '{print $7}' <<< ${output})

output=`./get_rusage 0`
exp_kmem_current=`echo "${output}" | grep "memory_kmem_usage" | cut -c 21-`
exp_umem_current=`echo "${output}" | grep "memory_numa_stat\[0\]" | cut -c 23-`
exp_mem_current=$((${exp_kmem_current}+${exp_umem_current}))

exp_kmem_max=`echo "${output}" | grep "memory_kmem_max_usage" | cut -c 25-`
exp_umem_max=`echo "${output}" | grep "memory_max_usage" | cut -c 20-`
exp_mem_max=$((${exp_kmem_max}+${exp_umem_max}))

exp_tsc_system=`echo "${output}" | grep "cpuacct_stat_system" | cut -c 23-`
exp_tsc_user=`echo "${output}" | grep "cpuacct_stat_user" | cut -c 21-`
exp_thread_current=`echo "${output}" | grep "num_threads" | head -1 | cut -c 15-`
exp_thread_max=`echo "${output}" | grep "max_num_threads" | cut -c 19-`

mck_mem_total=`echo "scale=3; ${mck_mem_total} - ${mem_current}" | bc`
mck_mem_total=${mck_mem_total%.*}
if [ 502 -le ${mck_mem_total} -a ${mck_mem_total} -lt 512 ]; then
	echo "TEST001: OK"
else
	echo "TEST001: NG, memory total value (exp:near512MiB val:${mck_mem_total}MiB)."
	result=-1
fi

exp_mem_current=$((${exp_mem_current} / 1024 / 1024))
mem_current=${mem_current%.*}
if [ ${mem_current} == ${exp_mem_current} ]; then
	echo "TEST002: OK"
else
	echo "TEST002: NG, memory current value (exp:${exp_mem_current}MiB val:${mem_current}MiB)"
	result=-1
fi

exp_mem_max=$((${exp_mem_max} / 1024 / 1024))
mem_max=${mem_max%.*}
if [ ${mem_max} == ${exp_mem_max} ]; then
	echo "TEST003: OK"
else
	echo "TEST003: NG, memory max value (exp:${exp_mem_max}MiB val:${mem_current}MiB)"
	result=-1
fi

exp_tsc_system=$((${exp_tsc_system}))
if [ ${tsc_system} == ${exp_tsc_system} ]; then
	echo "TEST004: OK"
else
	echo "TEST004: NG, tsc system value (exp:${exp_tsc_system} val:${tsc_system})"
	result=-1
fi

exp_tsc_user=$((${exp_tsc_user}))
if [ ${tsc_user} == ${exp_tsc_user} ]; then
	echo "TEST005: OK"
else
	echo "TEST005: NG, tsc user value (exp:${exp_tsc_system} val:${tsc_system})"
	result=-1
fi

exp_thread_current=$((${exp_thread_current}))
if [ ${thread_current} == ${exp_thread_current} ]; then
	echo "TEST006: OK"
else
	echo "TEST006: NG, current thread value (exp:${exp_thread_current} val:${thread_current})"
	result=-1
fi

exp_thread_max=$((${exp_thread_max}))
if [ ${thread_max} == ${exp_thread_max} ]; then
	echo "TEST007: OK"
else
	echo "TEST007: NG, max thread value (exp:${exp_thread_max} val:${thread_max})"
	result=-1
fi

output=`${MCSTAT} -n 1 20 | grep -c "\-\-\-\-\-\-\- memory"`
if [ ${output} == 1 ]; then
	echo "TEST008: OK"
else
	echo "TEST008: NG, header output frequency -n option setting."
	result=-1
fi

output=`${MCSTAT} 1 20 | grep -c "\-\-\-\-\-\-\- memory"`
if [ ${output} == 2 ]; then
	echo "TEST009: OK"
else
	echo "TEST009: NG, header output frequency -n option not setting."
	result=-1
fi

output=`${MCSTAT} -s | awk '{print toupper($0)}'`
output=`echo ${output} | cut -c 18-`
exp_status=`${IHKOSCTL} 0 get status`
if [ ${output} ==  ${exp_status} ]; then
	echo "TEST010: OK"
else
	echo "TEST010: NG, -s option get status.(exp:${exp_status} status:${output})"
	result=-1
fi

${MCSTAT} -h 2>&1 | grep -q "Usage"
if [ $? == 0 ]; then
	echo "TEST011: OK"
else
	echo "TEST011: NG, -h option setting."
	result=-1
fi

${MCSTAT} -s -h 2>&1 | grep -q "Usage"
if [ $? == 0 ]; then
	echo "TEST012: OK"
else
	echo "TEST012: NG, -h and other option setting."
	result=-1
fi

(time ${MCSTAT} 5 2) > ./tmp.log 2>&1
output=`cat ./tmp.log | tac | sed -n -e 3p | cut -c 8-12`
output=${output%.*}
if [ ${output} == 5 ]; then
	output=`cat ./tmp.log | sort | uniq -c | sort -nr | head -1 | cut -c 7-8`

	if [ ${output} == 2 ]; then
		echo "TEST013: OK"
	else
		echo "TEST013: NG, delay/count option setting. (lines mismatch)"
		result=-1
	fi
else
	echo "TEST013: NG, delay/count option setting. (times mismatch)"
	result=-1
fi

stdbuf -i0 -o0 -e0 ${MCSTAT} 1 > ./tmp.log 2>&1 &
sleep 10
kill `pidof mcstat`
output=`cat ./tmp.log | sort | uniq -c | sort -nr | head -1 | cut -c 6-7`
if [ ${output} == 11 ]; then
	echo "TEST014: OK"
else
	echo "TEST014: NG, delay option only setting."
	result=-1
fi

${MCSTAT} -k > ./tmp.log 2>&1
if [ $? == 0 ]; then
	cat ./tmp.log | grep -q "invalid option"

	if [ $? == 0 ]; then
		echo "TEST015: OK"
	else
		echo "TEST015: NG, invalid option setting. (log mismatch)"
		result=-1
	fi
else
	echo "TEST015: NG, invalid option setting. (result mismatch)"
	result=-1
fi

rm -f ./tmp.log

exit ${result}
