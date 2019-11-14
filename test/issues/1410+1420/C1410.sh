#!/bin/sh
uname -m
USELTP=1
USEOSTEST=0
BOOTPARAM="-c 1 -m 1G@0 -O"

. ../../common.sh

################################################################################
export MCEXEC
sh ./C1410T01run.sh

mcstop
unset BOOTPARAM
. $HOME/.mck_test_config
mcreboot
$MCEXEC ./C1420T01

for i in kill01:02 kill02:03 kill06:04 kill07:05 kill08:06 kill09:07 \
	 signal03:08 signal04:09 signal05:10; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	$MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1410T$id: $tp PASS ($ok)"
	else
		echo "*** C1410T$id: $tp FAIL (ok=$ok ng=%ng)"
	fi
done
