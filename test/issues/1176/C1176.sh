#!/bin/sh

USELTP=1
USEOSTEST=1

. ../../common.sh

"$MCEXEC" "$TESTMCK" -s getrusage -n 2 2>&1 | tee C1176T01.txt
if grep "RESULT: you need check rusage value" C1176T01.txt > /dev/null 2>&1;then
	echo "*** C1176T01: OK"
else
	echo "*** C1176T01: NG"
fi

"$MCEXEC" ./C1176T02
"$MCEXEC" ./C1176T03
"$MCEXEC" ./C1176T04

for i in kill01:05 kill12:06 pause02:07 sigaction01:08 ; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	$MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1176T$id: $tp OK ($ok)"
	else
		echo "*** C1176T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
