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

passed=`cat <<__EOL__
MADV_NORMAL
MADV_RANDOM
MADV_SEQUENTIAL
MADV_WILLNEED
MADV_DONTNEED
MADV_REMOVE
MADV_DONTFORK
MADV_DOFORK
MADV_DONTDUMP
MADV_DODUMP
MADV_WIPEONFORK
MADV_KEEPONFORK
__EOL__`
for madv in $passed
do
	grep "$madv" "${temp_log}" | grep -q "PASS:"
	if [ $? -ne 0 ]; then
		FAIL=1
	fi
done

rm -f "$temp_log"

if [ ${FAIL} -eq 1 ]; then
	echo "test NG."
else
	echo "test OK."
fi

mcstop
