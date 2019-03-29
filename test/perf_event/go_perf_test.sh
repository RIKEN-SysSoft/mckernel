#!/bin/sh

. ../common.sh

PERF_HW_ID_MAX=9
PERF_COUNT_HW_CACHE_MAX=6
PERF_COUNT_HW_CACHE_OP_MAX=2
PERF_COUNT_HW_CACHE_RESULT_MAX=1

PERF_TYPE_HARDWARE=0
PERF_TYPE_HW_CACHE=3

echo "[PERF_TYPE_HARDWARE all space]"
for id in `seq 0 ${PERF_HW_ID_MAX}`
do
	${MCK_DIR}/bin/mcexec ./perf_test 0 1 ${PERF_TYPE_HARDWARE} ${id}
done

echo "[HW_CACHE no exclude]"
for i in `seq 0 ${PERF_COUNT_HW_CACHE_MAX}`
do
	for j in `seq 0 ${PERF_COUNT_HW_CACHE_OP_MAX}`
	do
		for k in `seq 0 ${PERF_COUNT_HW_CACHE_RESULT_MAX}`
		do
			${MCK_DIR}/bin/mcexec ./perf_test 0 1 ${PERF_TYPE_HW_CACHE} `expr ${k} \* 65536 + ${j} \* 256 + ${i}`
		done
	done
done

echo "[HARDWARE exclude user space]"
for id in `seq 0 ${PERF_HW_ID_MAX}`
do
	${MCK_DIR}/bin/mcexec ./perf_test 1 1 ${PERF_TYPE_HARDWARE} ${id}
done

echo "[HW_CACHE exclude user space]"
for i in `seq 0 ${PERF_COUNT_HW_CACHE_MAX}`
do
	for j in `seq 0 ${PERF_COUNT_HW_CACHE_OP_MAX}`
	do
		for k in `seq 0 ${PERF_COUNT_HW_CACHE_RESULT_MAX}`
		do
			${MCK_DIR}/bin/mcexec ./perf_test 1 1 ${PERF_TYPE_HW_CACHE} `expr ${k} \* 65536 + ${j} \* 256 + ${i}`
		done
	done
done

echo "[HARDWARE exclude kernel space]"
for id in `seq 0 ${PERF_HW_ID_MAX}`
do
	${MCK_DIR}/bin/mcexec ./perf_test 2 1 ${PERF_TYPE_HARDWARE} ${id}
done

echo "[HW_CACHE exclude kernel space]"
for i in `seq 0 ${PERF_COUNT_HW_CACHE_MAX}`
do
	for j in `seq 0 ${PERF_COUNT_HW_CACHE_OP_MAX}`
	do
		for k in `seq 0 ${PERF_COUNT_HW_CACHE_RESULT_MAX}`
		do
			${MCK_DIR}/bin/mcexec ./perf_test 2 1 ${PERF_TYPE_HW_CACHE} `expr ${k} \* 65536 + ${j} \* 256 + ${i}`
		done
	done
done

