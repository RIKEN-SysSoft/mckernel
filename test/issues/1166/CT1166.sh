#!/bin/sh
USELTP=1
USEOSTEST=0

BOOTPARAM="-s -c 1-3 -m 1G"
. ../../common.sh

################################################################################
sudo $MCEXEC ./CT1166

for i in fork01:09 fork02:10 fork03:11 fork04:12 fork07:13 fork08:14 fork09:15 \
	 fork10:16 fork11:17; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** CT1166$id: $tp OK ($ok)"
	else
		echo "*** CT1166$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
