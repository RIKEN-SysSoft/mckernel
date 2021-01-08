#!/usr/bin/bash

USELTP=0
USEOSTEST=0

XPMEM_DIR=$HOME/usr
XPMEM_BUILD_DIR=/home/satoken/xpmem

. ../common.sh

sudo insmod ${XPMEM_DIR}/lib/modules/`uname -r`/xpmem.ko
sudo chmod og+rw /dev/xpmem

echo "*** XPMEM_TESTSUITE start *******************************"
cwd=`pwd`
cd ${XPMEM_BUILD_DIR}/test
${cwd}/mc_run.sh
cd ${cwd}

# xpmem basic test
${MCEXEC} ./XTP_001
${MCEXEC} ./XTP_002
${MCEXEC} ./XTP_003
${MCEXEC} ./XTP_004
${MCEXEC} ./XTP_005
${MCEXEC} ./XTP_006
sleep 3
${MCEXEC} ./XTP_007

${MCEXEC} ./XTP_901
${MCEXEC} ./XTP_902
${MCEXEC} ./XTP_903
${MCEXEC} ./XTP_904
${MCEXEC} ./XTP_905

sudo rmmod xpmem.ko
