#!/bin/sh
USELTP=1
USEOSTEST=1

BOOTPARAM="-c 12-15 -m 512M@4"
. ../../common.sh

echo ""
echo "*** get_rusage test"
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

echo ""
echo "*** LTP"
# mmap01 - 09, 12 - 15
for i in `seq -f "%02g" 1 1 9` `seq -f "%02g" 12 1 15` ; do
	$MCEXEC $LTPBIN/mmap$i
done

echo ""
echo "*** ostest, check ok"
for i in 0 2 4 6 10 11 32 34 36 38 40 41 42 43 48 ; do
	echo a > ./tmp
	$MCEXEC $TESTMCK -s mmap_file -n $i -- -f ./tmp \
		| grep "RESULT: ok" > /dev/null
	if [ $? -eq 0 ] ; then
		echo "[OK] mmap_file $i"
	else
		echo "[NG] mmap_file $i"
	fi
	rm -f ./tmp
done

echo ""
echo "*** otest, check mmap error."
for i in 8 9 `seq 16 1 31` ; do
	echo a > ./tmp
	$MCEXEC $TESTMCK -s mmap_file -n $i -- -f ./tmp \
		| grep "RESULT: mmap error." > /dev/null
	if [ $? -eq 0 ] ; then
		echo "[OK] mmap_file $i"
	else
		echo "[NG] mmap_file $i"
	fi
	rm -f ./tmp
done

echo ""
echo "*** oetest, check page fault"
for i in 1 3 5 7 12 13 14 15 33 35 37 39 44 45 46 47 ; do
	echo a > ./tmp
	$MCEXEC $TESTMCK -s mmap_file -n $i -- -f ./tmp > /dev/null
	if [ $? -eq 139 ] ; then
		echo "[OK] mmap_file $i"
	else
		echo "[NG] mmap_file $i"
	fi
	rm -f ./tmp
done

rm -f core.* mccore-filemap_sigbus.* mccore-test_mck.*

