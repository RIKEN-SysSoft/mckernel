#!/bin/sh
USELTP=1
USEOSTEST=0

BOOTPARAM="-c 1-7,17-23,9-15,25-31 -m 10G@0,10G@1"
. ../../common.sh

sudo $MCEXEC ./g310a 2>&1 | tee g310a.txt
if grep "fork: Permission denied" g310a.txt > /dev/null 2>&1 ; then
	echo "*** C731T001: g310a OK"
else
	echo "*** C731T001: g310a NG"
fi

for i in 01:002 02:003 03:004 04:005 07:006 08:007; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	$MCEXEC $LTPBIN/fork$tp 2>&1 | tee fork$tp.txt
	ok=`grep TPASS fork$tp.txt | wc -l`
	ng=`grep TFAIL fork$tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C731T$id: fork$tp OK ($ok)"
	else
		echo "*** C731T$id: fork$tp NG (ok=$ok ng=%ng)"
	fi
done
