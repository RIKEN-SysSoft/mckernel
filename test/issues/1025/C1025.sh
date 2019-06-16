#!/bin/sh

. ../../common.sh

PERF_TYPE_HARDWARE=0
PERF_COUNT_HW_CPU_CYCLES=0
PERF_COUNT_HW_INSTRUCTIONS=1
PERF_COUNT_HW_REF_CPU_CYCLES=9

echo "*** C1025T01 ******************************************"
echo "** Linux's result *************************************"
echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: none]"
./perf_test 0 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: user]"
./perf_test 1 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: kernel]"
./perf_test 2 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}
echo ""
echo "** McKernel's result *************************************"
echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: none]"
${MCEXEC} ./perf_test 0 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: user]"
${MCEXEC} ./perf_test 1 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: kernel]"
${MCEXEC} ./perf_test 2 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo ""

echo "*** C1025T02 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-A , Leader fd : YES , exclude: none]"
./perf_case_a 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-A , Leader fd : YES , exclude: user]"
./perf_case_a 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-A , Leader fd : YES , exclude: kernel]"
./perf_case_a 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-A , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_a 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-A , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_a 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-A , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_a 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo ""

echo "*** C1025T03 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-B , Leader fd : YES , exclude: none]"
./perf_case_b 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-B , Leader fd : YES , exclude: user]"
./perf_case_b 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-B , Leader fd : YES , exclude: kernel]"
./perf_case_b 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-B , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_b 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-B , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_b 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-B , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_b 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo ""

echo "*** C1025T04 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-C , Leader fd : YES , exclude: none]"
./perf_case_c 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-C , Leader fd : YES , exclude: user]"
./perf_case_c 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-C , Leader fd : YES , exclude: kernel]"
./perf_case_c 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-C , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_c 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-C , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_c 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-C , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_c 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo ""

echo "*** C1025T05 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-D , Leader fd : YES , exclude: none]"
./perf_case_d 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-D , Leader fd : YES , exclude: user]"
./perf_case_d 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-D , Leader fd : YES , exclude: kernel]"
./perf_case_d 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-D , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_d 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-D , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_d 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-D , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_d 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo ""

echo "*** C1025T06 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-A , Leader fd : NO , exclude: none]"
./perf_case_a 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-A , Leader fd : NO , exclude: user]"
./perf_case_a 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-A , Leader fd : NO , exclude: kernel]"
./perf_case_a 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-A , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_a 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-A , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_a 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-A , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_a 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo ""

echo "*** C1025T07 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-B , Leader fd : NO , exclude: none]"
./perf_case_b 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-B , Leader fd : NO , exclude: user]"
./perf_case_b 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-B , Leader fd : NO , exclude: kernel]"
./perf_case_b 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-B , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_b 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-B , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_b 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-B , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_b 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo ""

echo "*** C1025T08 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-C , Leader fd : NO , exclude: none]"
./perf_case_c 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-C , Leader fd : NO , exclude: user]"
./perf_case_c 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-C , Leader fd : NO , exclude: kernel]"
./perf_case_c 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-C , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_c 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-C , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_c 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-C , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_c 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo ""

echo "*** C1025T09 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-D , Leader fd : NO , exclude: none]"
./perf_case_d 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-D , Leader fd : NO , exclude: user]"
./perf_case_d 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-D , Leader fd : NO , exclude: kernel]"
./perf_case_d 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-D , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_d 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-D , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_d 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-D , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_d 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

