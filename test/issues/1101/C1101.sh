#!/bin/sh
USELTP=0
USEOSTEST=0
BOOTPARAM="-c 1-3 -m 1G@0 -e memdebug"

. ../../common.sh

################################################################################
if unxz < C1101T01.txt.xz | grep '^end 1999 ' > /dev/null 2>&1; then
	echo '*** C1101T01 PASS'
else
	echo '*** C1101T01 FAILED'
fi

$MCEXEC ./C1101T02
sleep 2
$IHKOSCTL 0 intr 200
sleep 2
$IHKOSCTL 0 clear_kmsg

for i in 2 3 4 5; do
	echo "*** C1101T0$i START"
	if $MCEXEC ./C1101T0$i; then
		sleep 2
		$IHKOSCTL 0 intr 200
		sleep 2
		l=`$IHKOSCTL 0 kmsg | grep "memory leak" | wc -l`
		$IHKOSCTL 0 clear_kmsg
		if [ $l = 0 ]; then
			echo "*** C1101T0$i PASS"
		else
			echo "*** C1101T0$i FAILED"
		fi
	else
		echo "*** C1101T0$i FAILED"
	fi
done
