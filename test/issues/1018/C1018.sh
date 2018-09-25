#!/bin/sh

USELTP=0
USEOSTEST=1

. ../../common.sh

${MCEXEC} ./CT_001
${MCEXEC} ./CT_002
