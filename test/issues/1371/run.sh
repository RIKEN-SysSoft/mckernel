#!/usr/bin/env bash
# run.sh COPYRIGHT FUJITSU LIMITED 2020

# load setting and booting mck.
USELTP=1
. ../../common.sh
chmod 777 /dev/mcos*

echo "test run."
FAIL=0

pushd ${LTPBIN} > /dev/null

temp_log=`mktemp tmp.XXXXXXXXXX`
script -f -c "${MCEXEC} ${LTPBIN}/madvise01" ${temp_log}
grep "madvise test for MADV_REMOVE" ${temp_log} | grep -q "PASS:"
result=$?
rm -f "$temp_log"

if [ $result -ne 0 ]; then
	FAIL=1
fi

popd > /dev/null

if [ ${FAIL} -eq 1 ]; then
	echo "test NG."
else
	echo "test OK."
fi

mcstop
