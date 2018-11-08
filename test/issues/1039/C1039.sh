#!/bin/sh
USELTP=1
USEOSTEST=0

BOOTPARAM="-c 1-7,17-23,9-15,25-31 -m 10G@0,10G@1"
. ../../common.sh

################################################################################
for i in fork02:01 fork03:02 execve01:03 execve02:04 execve03:05 mmap12:06; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo sh -c "PATH=$LTPBIN:$PATH $MCEXEC $LTPBIN/$tp" 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1039T$id: $tp OK ($ok)"
	else
		echo "*** C1039T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
