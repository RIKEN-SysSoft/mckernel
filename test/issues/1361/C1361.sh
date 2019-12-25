#!/bin/sh
USELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
uname -m
$MCEXEC ./C1361T01

for i in ppoll01:02 epoll_pwait01:03 pselect01:04 pselect03:05; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo PATH=$PATH:$LTPBIN $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep PASS $tp.txt | wc -l`
	ng=`grep FAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1361T$id: $tp PASS ($ok)"
	else
		echo "*** C1361T$id: $tp FAIL (ok=$ok ng=%ng)"
	fi
done
