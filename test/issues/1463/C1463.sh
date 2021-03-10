#/bin/sh

USELTP=0
USEOSTEST=0

. ../../common.sh

issue="1463"
tid=01

TEST_DIR="/tmp/test"
ABS_PATH="${TEST_DIR}"
REL_PATH="./test"
ABS_LN="${TEST_DIR}_1463_abs_ln"
REL_LN="${TEST_DIR}_1463_rel_ln"

mkdir -p ${TEST_DIR}
touch ${TEST_DIR}/L.dir

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ln -fns ${ABS_PATH} ${ABS_LN}
mcexec readlink ${ABS_LN}/L.dir | tee ./${tname}.txt
cnt=`grep "a.dir" ./${tname}.txt | wc -l`
if [ ${cnt} -eq 1 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ln -fns ${REL_PATH} ${REL_LN}
mcexec readlink ${REL_LN}/L.dir | tee ./${tname}.txt
cnt=`grep "a.dir" ./${tname}.txt | wc -l`
if [ ${cnt} -eq 1 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
mcexec cat /sys/devices/system/cpu/offline | tee ./${tname}.txt
echo "** (expected blank output)"
lines=`grep -e "[0-9]" ./${tname}.txt | wc -l`
if [ ${lines} -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

