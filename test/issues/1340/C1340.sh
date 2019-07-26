#!/bin/sh

USELTP=0
USEOSTEST=0

. ../../common.sh

arch=`uname -p`
if [ -f "./${arch}_config" ]; then
	. ./${arch}_config
else
	echo "$1 is unexpected arch"
	exit 1
fi

# clean corefils
rm ./mccore* ./core.*

ulimit_c_bk=`ulimit -Sc`
# set ulimit -c unlimited to dump core
ulimit -c unlimited


issue=1340

tid=01
tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
signum=11
if [ "${arch}" = "x86_64" ]; then
	signame=11
elif [ "${arch}" = "aarch_64" ]; then
	signame=SEGV
fi

echo "** Check signal in coredump. GPE"
${MCEXEC} ./segv

# Find mccore*
CORE=`ls -1 | grep "^mccore"`

if [ ! -z $CORE ]; then
	echo "[ OK ] core for McKernel process found"
else
	echo "[ NG ] core for McKernel process not found"
	exit 1
fi

gdb ./segv --core=./${CORE} -x ./cmd/C${issue}.cmd 2>/dev/null \
| tee ./${tname}.txt

num=`grep "Program terminated with signal ${signame}" ./${tname}.txt | wc -l`

if [ ${num} -eq 1 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
# clean corefils
rm ./mccore* ./core.*
let tid++
echo ""

idx=0
for signum in ${SIG_LIST[@]}
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	echo "** Check signal in coredump. raise ${signum}"
	${MCEXEC} ./raise_sig ${signum}

	# Find mccore*
	CORE=`ls -1 | grep "^mccore"`

	if [ ! -z $CORE ]; then
		echo "[ OK ] core for McKernel process found"
	else
		echo "[ NG ] core for McKernel process not found"
		exit 1
	fi

	gdb ./segv --core=./${CORE} -x ./cmd/C${issue}.cmd 2>/dev/null \
	| tee ./${tname}.txt

	num=`grep "Program terminated with signal ${NAME_LIST[${idx}]}" ./${tname}.txt | wc -l`

	if [ ${num} -eq 1 ]; then
		echo "*** ${tname} PASSED ******************************"
	else
		echo "*** ${tname} FAILED ******************************"
	fi
	# clean corefils
	rm ./mccore* ./core.*
	let tid++
	echo ""
	let idx++
done

exit 0


tid=03
echo "*** C${issue}T${tid} start *******************************"
echo "** Check signal in coredump. raise SIGILL"
signum=4
${MCEXEC} ./raise_sig ${signum}

# Find mccore*
CORE=`ls -1 | grep "^mccore"`

if [ ! -z $CORE ]; then
	echo "[ OK ] core for McKernel process found"
else
	echo "[ NG ] core for McKernel process not found"
	exit 1
fi

gdb ./segv --core=./${CORE} -x ./cmd/C${issue}.cmd 2>/dev/null \
| tee ./C${issue}T${tid}.txt

num=`grep "Program terminated with signal ${signum}" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -eq 1 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
# clean corefils
rm ./mccore* ./core.*
echo ""

tid=04
echo "*** C${issue}T${tid} start *******************************"
echo "** Check signal in coredump. raise SIGABRT"
signum=6
${MCEXEC} ./raise_sig ${signum}

# Find mccore*
CORE=`ls -1 | grep "^mccore"`

if [ ! -z $CORE ]; then
	echo "[ OK ] core for McKernel process found"
else
	echo "[ NG ] core for McKernel process not found"
	exit 1
fi

gdb ./segv --core=./${CORE} -x ./cmd/C${issue}.cmd 2>/dev/null \
| tee ./C${issue}T${tid}.txt

num=`grep "Program terminated with signal ${signum}" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -eq 1 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
# clean corefils
rm ./mccore* ./core.*
echo ""

tid=05
echo "*** C${issue}T${tid} start *******************************"
echo "** Check signal in coredump. raise SIGFPE"
signum=8
${MCEXEC} ./raise_sig ${signum}

# Find mccore*
CORE=`ls -1 | grep "^mccore"`

if [ ! -z $CORE ]; then
	echo "[ OK ] core for McKernel process found"
else
	echo "[ NG ] core for McKernel process not found"
	exit 1
fi

gdb ./segv --core=./${CORE} -x ./cmd/C${issue}.cmd 2>/dev/null \
| tee ./C${issue}T${tid}.txt

num=`grep "Program terminated with signal ${signum}" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -eq 1 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
# clean corefils
rm ./mccore* ./core.*
echo ""

tid=06
echo "*** C${issue}T${tid} start *******************************"
echo "** Check signal in coredump. raise SIGSEGV"
signum=11
${MCEXEC} ./raise_sig ${signum}

# Find mccore*
CORE=`ls -1 | grep "^mccore"`

if [ ! -z $CORE ]; then
	echo "[ OK ] core for McKernel process found"
else
	echo "[ NG ] core for McKernel process not found"
	exit 1
fi

gdb ./segv --core=./${CORE} -x ./cmd/C${issue}.cmd 2>/dev/null \
| tee ./C${issue}T${tid}.txt

num=`grep "Program terminated with signal ${signum}" ./C${issue}T${tid}.txt | wc -l`

if [ ${num} -eq 1 ]; then
	echo "*** C${issue}T${tid} PASSED ******************************"
else
	echo "*** C${issue}T${tid} FAILED ******************************"
fi
# clean corefils
rm ./mccore* ./core.*
echo ""

# restore ulimit -c
ulimit -c ${ulimit_c_bk}
