#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=1

. ../../../../common.sh

${MCEXEC} ./CT_001
${MCEXEC} ./CT_002
${MCEXEC} ./CT_003
sleep 2
${MCEXEC} ./CT_004
${MCEXEC} ./CT_005
${MCEXEC} ./CT_006
${MCEXEC} ./CT_007
${MCEXEC} ./CT_008
${MCEXEC} ./CT_009
${MCEXEC} ./CT_010
${MCEXEC} ./CT_011
${MCEXEC} ${TESTMCK} -s ptrace -n 19
${MCEXEC} ${TESTMCK} -s ptrace -n 20
