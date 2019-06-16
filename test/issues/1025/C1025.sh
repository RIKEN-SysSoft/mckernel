#!/bin/sh

. ../../common.sh

PERF_TYPE_HARDWARE=0
PERF_COUNT_HW_CPU_CYCLES=0
PERF_COUNT_HW_INSTRUCTIONS=1
PERF_COUNT_HW_REF_CPU_CYCLES=9

ng=0
echo "*** C1025T01 ******************************************"
echo "** Linux's result *************************************"
echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: none]"
./perf_test 0 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: user]"
./perf_test 1 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: kernel]"
./perf_test 2 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo ""
echo "** McKernel's result *************************************"
echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: none]"
${MCEXEC} ./perf_test 0 1 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: user]"
${MCEXEC} ./perf_test 1 1 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[type: HARDWARE, counter: HW_REF_CPU_CYCLES, exclude: kernel]"
${MCEXEC} ./perf_test 2 1 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T01 PASSED"
else
	echo "** C1025T01 FAILED"
fi
echo ""

ng=0
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
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-A , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_a 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-A , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_a 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-A , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_a 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T02 PASSED"
else
	echo "** C1025T02 FAILED"
fi
echo ""

ng=0
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
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-B , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_b 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-B , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_b 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-B , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_b 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T03 PASSED"
else
	echo "** C1025T03 FAILED"
fi
echo ""

ng=0
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
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-C , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_c 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-C , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_c 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-C , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_c 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T04 PASSED"
else
	echo "** C1025T04 FAILED"
fi
echo ""

ng=0
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
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-D , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_d 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-D , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_d 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-D , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_d 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | head -n1 | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | head -n1 | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | head -n1 | grep -o [0-9]*`
echo -n "check user val 1st:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val 1st:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | tail -n1 | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | tail -n1 | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | tail -n1 |grep -o [0-9]*`
echo -n "check user val 2nd:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val 2nd:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T05 PASSED"
else
	echo "** C1025T05 FAILED"
fi
echo ""

ng=0
echo "*** C1025T06 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-E , Leader fd : YES , exclude: none]"
./perf_case_e 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-E , Leader fd : YES , exclude: user]"
./perf_case_e 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-E , Leader fd : YES , exclude: kernel]"
./perf_case_e 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-E , Leader fd : YES , exclude: none]"
${MCEXEC} ./perf_case_e 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES}

echo "[ CASE-E , Leader fd : YES , exclude: user]"
${MCEXEC} ./perf_case_e 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-E , Leader fd : YES , exclude: kernel]"
${MCEXEC} ./perf_case_e 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T06 PASSED"
else
	echo "** C1025T06 FAILED"
fi
echo ""

ng=0
echo "*** C1025T07 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-A , Leader fd : NO , exclude: none]"
./perf_case_a 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-A , Leader fd : NO , exclude: user]"
./perf_case_a 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-A , Leader fd : NO , exclude: kernel]"
./perf_case_a 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-A , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_a 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-A , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_a 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-A , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_a 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T07 PASSED"
else
	echo "** C1025T07 FAILED"
fi
echo ""

ng=0
echo "*** C1025T08 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-B , Leader fd : NO , exclude: none]"
./perf_case_b 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-B , Leader fd : NO , exclude: user]"
./perf_case_b 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-B , Leader fd : NO , exclude: kernel]"
./perf_case_b 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-B , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_b 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-B , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_b 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-B , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_b 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T08 PASSED"
else
	echo "** C1025T08 FAILED"
fi
echo ""

ng=0
echo "*** C1025T09 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-C , Leader fd : NO , exclude: none]"
./perf_case_c 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-C , Leader fd : NO , exclude: user]"
./perf_case_c 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-C , Leader fd : NO , exclude: kernel]"
./perf_case_c 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-C , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_c 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-C , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_c 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-C , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_c 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T09 PASSED"
else
	echo "** C1025T09 FAILED"
fi
echo ""

ng=0
echo "*** C1025T10 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-D , Leader fd : NO , exclude: none]"
./perf_case_d 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-D , Leader fd : NO , exclude: user]"
./perf_case_d 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-D , Leader fd : NO , exclude: kernel]"
./perf_case_d 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-D , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_d 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-D , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_d 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-D , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_d 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | head -n1 | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | head -n1 | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | head -n1 | grep -o [0-9]*`
echo -n "check user val 1st:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val 1st:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | tail -n1 | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | tail -n1 | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | tail -n1 |grep -o [0-9]*`
echo -n "check user val 2nd:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val 2nd:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T10 PASSED"
else
	echo "** C1025T10 FAILED"
fi
echo ""

ng=0
echo "*** C1025T11 ******************************************"
echo "** Linux's result *************************************"
echo "[ CASE-E , Leader fd : NO , exclude: none]"
./perf_case_e 0 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-E , Leader fd : NO , exclude: user]"
./perf_case_e 1 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-E , Leader fd : NO , exclude: kernel]"
./perf_case_e 2 2 ${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./lnx_user_val.txt
echo""
echo "** McKernel's result *************************************"
echo "[ CASE-E , Leader fd : NO , exclude: none]"
${MCEXEC} ./perf_case_e 0 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES}

echo "[ CASE-E , Leader fd : NO , exclude: user]"
${MCEXEC} ./perf_case_e 1 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_kernel_val.txt

echo "[ CASE-E , Leader fd : NO , exclude: kernel]"
${MCEXEC} ./perf_case_e 2 2 \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_CPU_CYCLES} \
${PERF_TYPE_HARDWARE} ${PERF_COUNT_HW_REF_CPU_CYCLES} \
| tee ./mck_user_val.txt

lnx_user_val=`grep "REF_CPU" ./lnx_user_val.txt | grep -o [0-9]*`
mck_user_val=`grep "REF_CPU" ./mck_user_val.txt | grep -o [0-9]*`
mck_kernel_val=`grep "REF_CPU" ./mck_kernel_val.txt | grep -o [0-9]*`
echo -n "check user val:"
./check_val.sh ${lnx_user_val} ${mck_user_val} 0.9 1.1
ng+=$?
echo -n "check kernel val:"
./check_val.sh ${mck_user_val} ${mck_kernel_val} 0 0.01
ng+=$?
if [ $ng -eq 0 ]; then
	echo "** C1025T11 PASSED"
else
	echo "** C1025T11 FAILED"
fi
