#!/bin/sh
# 1287.sh COPYRIGHT FUJITSU LIMITED 2020

. $HOME/.mck_test_config

BOOTPARAM="-c 12-15 -m 512M@4 -O"
USELTP=1
FAIL=0

. ../../../common.sh

echo "issue-1287 test run."

${MCEXEC} ./1287_arm64
if [ $? -eq 0 ]; then
	echo "TEST001:OK."
else
	echo "TEST001:NG."
	FAIL=1
fi

echo "LTP: ptrace run."

ltp=("01" "02" "03" "05")

pushd ${LTPBIN} > /dev/null
for num in ${ltp[@]}
do
	${MCEXEC} ./ptrace${num}
	if [ $? -ne 0 ]; then
		FAIL=1
	fi
done
popd > /dev/null

if [ ${FAIL} -eq 0 ]; then
	echo "issue-1287 test OK."
else
	echo "issue-1287 test NG."
fi

mcstop
