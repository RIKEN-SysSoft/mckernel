#!/bin/sh
USELTP=1
USEOSTEST=0

BOOTPARAM="-c 1-7,17-23,9-15,25-31 -m 10G@0,10G@1"
. ../../common.sh

################################################################################
$MCEXEC ./C1009T01

for i in kill01:02 kill12:03 pause02:04 sigaction01:05 ; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	$MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1009T$id: $tp OK ($ok)"
	else
		echo "*** C1009T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
