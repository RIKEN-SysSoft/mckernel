#!/bin/sh
USELTP=0
USEOSTEST=1

BOOTPARAM="-c 1-7 -m 4G@0"
. ../../common.sh

$MCEXEC ./C765

$MCEXEC $TESTMCK -s mem_limits -n 0 -- -f mmap -s 7340032 -c 1

if $SBINDIR/ihkosctl 0 kmsg | grep -i bad > /dev/null 2>&1; then
	$SBINDIR/ihkosctl 0 kmsg
	echo C765T09 NG
else
	echo C765T09 OK
fi
