#!/bin/sh

. ../../common.sh

PERF_TYPE_HARDWARE=0
PERF_COUNT_HW_REF_CPU_CYCLES=9

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: none]"
${MCEXEC} ./perf_test 0 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: user]"
${MCEXEC} ./perf_test 1 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: kernel]"
echo "[HARDWARE exclude kernel space]"
${MCEXEC} ./perf_test 2 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}
