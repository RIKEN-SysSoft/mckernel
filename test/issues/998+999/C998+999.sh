#!/bin/sh
USELTP=0
USEOSTEST=1

BOOTPARAM="-c 1-7,9-15,17-23,25-31 -m 10G@0,10G@1 -r 1-7:0+9-15:8+17-23:16+25-31:24"
. ../../common.sh

for i in {1..10}; do
	for j in {1..100}; do
		$MCEXEC "$TESTMCK" -s wait4 -n 3 > testmck.log 2>&1
		if [ $? != 0 ]; then
			echo "****** ERROR ******"
			cat testmck.log
			exit 1
		fi
		echo -n .
	done
	echo
	echo "*** $i"00" ****************************"
done

echo "*** C998+999 OK ****************************"
