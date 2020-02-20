#!/bin/sh
USELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
for i in rt_sigtimedwait01:01 kill02:02 kill09:03 kill12:04 llseek01:05 \
	 signal01:06 signal02:07 signal03:08 getrusage03:09 write05:10; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo PATH=$PATH:$LTPBIN $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1378T$id: $tp PASS ($ok)"
	else
		echo "*** C1378T$id: $tp FAIL (ok=$ok ng=$ng)"
	fi
done
