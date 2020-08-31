#!/bin/sh
USELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
for i in shmctl05:01 shmctl01:02 shmctl02:03 shmctl03:04 shmctl04:05 \
	 remap_file_pages01:06 remap_file_pages02:07; do
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
		echo "*** C1379T$id: $tp PASS ($ok)"
	else
		echo "*** C1379T$id: $tp FAIL (ok=$ok ng=$ng)"
	fi
done
