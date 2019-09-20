#!/bin/sh
USELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
$MCEXEC ./C1221T01

for i in getrusage01:02 getrusage02:03 getrusage03:04 getrusage04:05; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	PATH=$PATH:$LTPBIN $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1221T$id: $tp PASS ($ok)"
	else
		echo "*** C1221T$id: $tp FAIL (ok=$ok ng=%ng)"
	fi
done
