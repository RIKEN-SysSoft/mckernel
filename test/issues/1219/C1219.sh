#!/bin/sh

USELTP=0
USEOSTEST=0

. ../../common.sh

TP_SUB=./segv_in_sub
TP_MAIN=./segv_in_main

NUM_THREADS=6
arch=`uname -p`

# clean corefils
rm ./mccore* ./core.*

ulimit_c_bk=`ulimit -Sc`
# set ulimit -c unlimited to dump core
ulimit -c unlimited

${MCEXEC} ./segv_in_sub

# Find mccore*
CORE=`ls -1 | grep "^mccore"`

if [ ! -z $CORE ]; then
	echo "[ OK ] core for McKernel process found"
else
	echo "[ NG ] core for McKernel process not found"
	exit 1
fi

issue=1219
tid=01
echo "*** C${issue}T${tid} start *******************************"
echo "** Check number of threads"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "LWP" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -eq ${NUM_THREADS} ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=02
echo "*** C${issue}T${tid} start *******************************"
echo "** Check backtrace"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "^#[0-9]*\s* 0x[0-9]*" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=03
echo "*** C${issue}T${tid} start *******************************"
echo "** Check info register"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

if [ "${arch}" == "x86_64" ]; then
	num=`grep "^rip\s*0x.*" ./C${issue}T${tid}.txt | wc -l`
elif [ "${arch}" == "aarch64" ]; then
	num=`grep "^pc\s*0x.*" ./C${issue}T${tid}.txt | wc -l`
else
	num=0
fi

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=04
echo "*** C${issue}T${tid} start *******************************"
echo "** Check switching thread"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "Switching to thread ${NUM_THREADS}" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=05
echo "*** C${issue}T${tid} start *******************************"
echo "** Check backtrace after switching thread"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "^#[0-9]*\s* 0x[0-9]*" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=06
echo "*** C${issue}T${tid} start *******************************"
echo "** Check info register after switching thread"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

if [ "${arch}" == "x86_64" ]; then
	num=`grep "^rip\s*0x.*" ./C${issue}T${tid}.txt | wc -l`
elif [ "${arch}" == "aarch64" ]; then
	num=`grep "^pc\s*0x.*" ./C${issue}T${tid}.txt | wc -l`
else
	num=0
fi

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

# clean corefils
rm ./mccore* ./core.*

${MCEXEC} ./segv_in_main

# Find mccore*
CORE=`ls -1 | grep "^mccore"`

if [ ! -z $CORE ]; then
	echo "[ OK ] core for McKernel process found"
else
	echo "[ NG ] core for McKernel process not found"
	exit 1
fi

tid=07
echo "*** C${issue}T${tid} start *******************************"
echo "** Check number of threads"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "LWP" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -eq ${NUM_THREADS} ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=08
echo "*** C${issue}T${tid} start *******************************"
echo "** Check backtrace"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "^#[0-9]*\s* 0x[0-9]*" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=09
echo "*** C${issue}T${tid} start *******************************"
echo "** Check info register"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

if [ "${arch}" == "x86_64" ]; then
	num=`grep "^rip\s*0x.*" ./C${issue}T${tid}.txt | wc -l`
elif [ "${arch}" == "aarch64" ]; then
	num=`grep "^pc\s*0x.*" ./C${issue}T${tid}.txt | wc -l`
else
	num=0
fi

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=10
echo "*** C${issue}T${tid} start *******************************"
echo "** Check switching thread"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "Switching to thread ${NUM_THREADS}" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=11
echo "*** C${issue}T${tid} start *******************************"
echo "** Check backtrace after switching thread"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "^#[0-9]*\s* 0x[0-9]*" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

tid=12
echo "*** C${issue}T${tid} start *******************************"
echo "** Check info register after switching thread"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

if [ "${arch}" == "x86_64" ]; then
	num=`grep "^rip\s*0x.*" ./C${issue}T${tid}.txt | wc -l`
elif [ "${arch}" == "aarch64" ]; then
	num=`grep "^pc\s*0x.*" ./C${issue}T${tid}.txt | wc -l`
else
	num=0
fi

if [ ${num} -gt 0 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

# clean corefils
rm ./mccore* ./core.*

${MCEXEC} ./segv_after_join

# restore ulimit -c
ulimit -c ${ulimit_c_bk}

# Find mccore*
CORE=`ls -1 | grep "^mccore"`

if [ ! -z $CORE ]; then
	echo "[ OK ] core for McKernel process found"
else
	echo "[ NG ] core for McKernel process not found"
	exit 1
fi

tid=13
echo "*** C${issue}T${tid} start *******************************"
echo "** Check number of threads"
gdb ${TP_SUB} --core=./${CORE} -x ./cmd/C${issue}T${tid}.cmd 2>/dev/null \
| sed -n '/TESTOUT_START/,$p' | tee ./C${issue}T${tid}.txt

num=`grep "LWP" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -eq 1 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
echo ""

