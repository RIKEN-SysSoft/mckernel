#!/bin/sh
USELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
uname -m
for i in msgrcv05:01 msgsnd05:02 semctl01:03 semop05:04 kill01:05 \
	 kill02:06 kill06:07 kill07:08 kill08:09 kill09:10; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo PATH=$PATH:$LTPBIN $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ok = 0 -a $ng = 0 ]; then
		ok=`awk '/^passed/{print $2}' $tp.txt`
		ng=`awk '/^failed/{print $2}' $tp.txt`
	fi
	if [ $ng = 0 ]; then
		echo "*** C1505T$id: $tp PASS ($ok)"
	else
		echo "*** C1505T$id: $tp FAIL (ok=$ok ng=%ng)"
	fi
done
