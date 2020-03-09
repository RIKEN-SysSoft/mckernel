#!/bin/sh
# 1370.sh COPYRIGHT FUJITSU LIMITED 2020

. $HOME/.mck_test_config

BOOTPARAM="-c 12-15 -m 512M@4 -O"
USELTP=1
FAIL=0

. ../../common.sh

# for access02 setting
chmod 666 /dev/mcos*

echo "issue-1370 test run."

ltp=("access01" "access02" "access03" "access04" "faccessat01")

for tp in ${ltp[@]}
do
	pushd ${LTPBIN} > /dev/null
	${MCEXEC} ${LTPBIN}/${tp}
	if [ $? -ne 0 ]; then
		FAIL=1
	fi
	popd > /dev/null
done

if [ ${FAIL} -eq 1 ]; then
	echo "issue-1370 test NG."
else
	echo "issue-1370 test OK."
fi

mcstop
