#!/usr/bin/env bash
# run.sh COPYRIGHT FUJITSU LIMITED 2020

# load setting and booting mck.
USELTP=1
. ../../common.sh
chmod 777 /dev/mcos*

echo "test run."
ltp=`cat <<__EOL__
madvise08
madvise10
__EOL__`

FAIL=0
for tp in $ltp
do
	pushd ${LTPBIN} > /dev/null
	${MCEXEC} ${LTPBIN}/${tp}
	if [ $? -ne 0 ]; then
		FAIL=1
	fi
	popd > /dev/null
done

if [ ${FAIL} -eq 1 ]; then
	echo "test NG."
else
	echo "test OK."
fi

mcstop
