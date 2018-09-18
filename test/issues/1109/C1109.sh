#!/bin/sh
USELTP=0
USEOSTEST=1

BOOTPARAM="-c 1-7 -m 10G@0"
. ../../common.sh

maxmem=`$SBINDIR/ihkosctl 0 query mem | cut -d '@' -f 1`
mem95p=`expr $maxmem \* 95 / 100`
mem110p=`expr $maxmem \* 110 / 100`

for i in 10240:9961472:01 2097152:2040109466:02 unlimited:$mem95p:03; do
	ul=`echo $i|sed 's/:.*//'`
	st=`echo $i|sed -e 's/^[^:]*://' -e 's/:[^:]*$//'`
	id=`echo $i|sed 's/.*://'`

	sudo sh -c "ulimit -s $ul; $MCEXEC $TESTMCK -s mem_stack_limits -n 0 -- -s $st" 2>&1 | tee C1109T$id.txt
	if grep "RESULT: ok" C1109T$id.txt > /dev/null 2>&1; then
		echo "*** C1109T$id: OK"
	else
		echo "*** C1109T$id: NG"
	fi
done

for i in 10M:9961472:04 2G:2040109466:05 100000G:$mem95p:06; do
	ul=`echo $i|sed 's/:.*//'`
	st=`echo $i|sed -e 's/^[^:]*://' -e 's/:[^:]*$//'`
	id=`echo $i|sed 's/.*://'`

	$MCEXEC -s 2M,$ul $TESTMCK -s mem_stack_limits -n 0 -- -s $st 2>&1 | tee C1109T$id.txt
	if grep "RESULT: ok" C1109T$id.txt > /dev/null 2>&1; then
		echo "*** C1109T$id: OK"
	else
		echo "*** C1109T$id: NG"
	fi
done
