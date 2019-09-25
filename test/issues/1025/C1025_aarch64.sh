#!/bin/sh

. ../../common.sh

PERF_TYPE_HARDWARE=0
PERF_COUNT_HW_REF_CPU_CYCLES=9

ng=0
echo "*** C1025T01 ******************************************"
echo "** Linux's result *************************************"
echo "* REF_CPU_CYCLES event is NOT supported Linux on aarch64"
echo ""
echo "** McKernel's result *************************************"
echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: none]"
${MCEXEC} ./perf_test 0 1 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_all_val.txt

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: user]"
${MCEXEC} ./perf_test 1 1 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: kernel]"
${MCEXEC} ./perf_test 2 1 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_user_val.txt

mck_all_val=`grep "REF_CPU" ./mck_all_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`

if [ "x${mck_all_val}" != "x" ] && [ "x${mck_user_val}" != "x" ] && \
[ "x${mck_kernel_val}" != "x" ] ; then
	echo "** C1025T01 PASSED"
else
	echo "** C1025T01 FAILED"
fi
echo ""

