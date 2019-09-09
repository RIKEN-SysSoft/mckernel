#!/bin/sh

USELTP=0
USEOSTEST=0

BOOTPARAM="-c 1-7-m 10G@0,10G@1 -O"
. ../../common.sh

issue=1356
tid=01

arch=`uname -p`

if [ "${arch}" == "x86_64" ]; then
	ARCHDIR="smp-x86"
elif [ "${arch}" == "aarch64" ]; then
	ARCHDIR="smp-arm64"
else
	echo "Not supported architecture."
	exit 1
fi

ECLAIR=${BIN}/eclair
MCKDUMP=/tmp/issue${issue}_mckdump
MCKIMG=${BIN}/../${ARCHDIR}/kernel/mckernel.img
LOG=./C${issue}_eclair.txt

# dump mckdump
sleep 1
echo "** Dump Mckernel-dump"
sudo ${IHKOSCTL} 0 dump -d 24 ${MCKDUMP}
sleep 1
echo "** DONE ${MCKDUMP}"

echo ""
echo "***** Result of eclair ************************"
expect -c "
set timeout 20
spawn ${ECLAIR} -d ${MCKDUMP} -k ${MCKIMG} -l

expect \"(eclair)\"
send \"set pagination 0\n\"

expect \"(eclair)\"
send \"info threads\n\"

expect \"(eclair)\"
send \"thread 3\n\"

expect \"(eclair)\"
send \"info register\n\"

expect \"(eclair)\"
send \"bt\n\"

expect \"(eclair)\"
send \"quit\n\

" | tee ./${LOG}

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
echo "** Check reading symbols"
grep -o "Reading symbols.*mckernel.img...done." ${LOG}
if [ $? -eq 0 ]; then
    echo "*** ${tname} PASSED ******************************"
else
    echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
echo "** Check detected number of cpus"
expect_num=`${IHKOSCTL} 0 kmsg | grep "# of cpus" | cut -d " " -f 7`
cat ${LOG} | awk '/info threads/,/thread 3/' > ${tname}.txt
thread_num=`cat ${tname}.txt | grep "New Thread" | wc -l`
cpu_num=$(( $thread_num + 1 ))

echo "** CPU_NUM: ${cpu_num}  (expected ${expect_num})"

if [ ${cpu_num} -eq ${expect_num} ]; then
    echo "*** ${tname} PASSED ******************************"
else
    echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
echo "** Check switch thread"
cat ${LOG} | awk '/thread 3/,/info register/' > ${tname}.txt

grep "Switching to thread" ./${tname}.txt

if [ $? -eq 0 ]; then
    echo "*** ${tname} PASSED ******************************"
else
    echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
echo "** Check info register"
cat ${LOG} | awk '/info register/,/bt/' > ${tname}.txt

grep "rip.*cpu_safe_halt.*" ./${tname}.txt

if [ $? -eq 0 ]; then
    echo "*** ${tname} PASSED ******************************"
else
    echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
echo "** Check back trace"
cat ${LOG} | awk '/bt/,/EOF/' > ${tname}.txt

grep "cpu_safe_halt" ./${tname}.txt

if [ $? -eq 0 ]; then
    echo "*** ${tname} PASSED ******************************"
else
    echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

