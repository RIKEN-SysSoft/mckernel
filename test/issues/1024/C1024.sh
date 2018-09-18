#!/bin/sh
USELTP=1
USEOSTEST=0

BOOTPARAM="-c 1-7,17-23,9-15,25-31 -m 10G@0,10G@1"
. ../../common.sh

################################################################################
rm -f mcexec
ln -s $MCEXEC
./C1024T01
./mcexec ./C1024T02

for i in process_vm_readv02:03 process_vm_readv03:04 process_vm_writev02:05; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1024T$id: $tp OK ($ok)"
	else
		echo "*** C1024T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
