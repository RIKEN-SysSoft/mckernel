#!/bin/sh
USELTP=0
USEOSTEST=0

BOOTPARAM="-c 12-15 -m 512M@4"
. ../../common.sh

echo a > ./tmp
BEFORE_STR=`./get_rusage 0 | grep "memory_stat_mapped_file"`
$MCEXEC ./filemap_sigbus ./tmp
AFTER_STR=`./get_rusage 0 | grep "memory_stat_mapped_file"`

if [ "${BEFORE_STR}" == "${AFTER_STR}" ]; then
	echo "TEST OK."
else
	echo "TEST NG."
	echo "${BEFORE_STR}"
	echo "${AFTER_STR}"
fi

rm -f ./tmp

