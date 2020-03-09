#!/bin/sh
# 1382.sh COPYRIGHT FUJITSU LIMITED 2020

. $HOME/.mck_test_config

BOOTPARAM="-c 12-15 -m 4G@4,4G@5,4G@6,4G@7 -O"
USELTP=1
FAIL=0
LTPLIST="${PWD}/ltp_list.txt"

. ../../common.sh

echo "issue-1382 test run."

pushd ${LTPBIN} > /dev/null
while read line
do
	${MCEXEC} ./${line}
	if [ $? -ne 0 ]; then
		FAIL=1
	fi
done < ${LTPLIST}
popd > /dev/null

if [ ${FAIL} -eq 1 ]; then
	echo "issue-1382 test NG."
else
	echo "issue-1382 test OK."
fi

mcstop
