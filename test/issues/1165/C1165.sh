#!/bin/sh
USELTP=1
USEOSTEST=1

BOOTPARAM="-c 1-7,17-23,9-15,25-31 -m 10G@0,10G@1"
. ../../common.sh

################################################################################
$MCEXEC ./C1165T01

sudo sh "$OSTESTDIR"/util/rmmod_test_drv.sh > /dev/null 2>&1
sudo sh "$OSTESTDIR"/util/insmod_test_drv.sh
echo a > mmapfile
sudo timeout -s 9 3 $MCEXEC "$TESTMCK" -s force_exit -n 0 -- -d /dev/test_mck/mmap_dev -f mmapfile
rm -f mmapfile
sudo sh "$OSTESTDIR"/util/rmmod_test_drv.sh
"$SBINDIR"/ihkosctl 0 clear_kmsg
"$SBINDIR"/ihkosctl 0 ioctl 40000000 1
"$SBINDIR"/ihkosctl 0 ioctl 40000000 2
"$SBINDIR"/ihkosctl 0 kmsg | sed 's/[^:]*://' | awk '$2 == "processes" {p = $1} $2 == "threads" {t = $1}END{if (p != 0 || t != 0) {print "*** C1165T02 NG"} else {print "*** C1165T02 OK"}}'

for i in clone01:03 clone03:04 clone04:05 clone06:06 clone07:07 fork01:08 \
	 fork02:09 fork03:10 fork04:11 fork07:12 fork08:13 fork09:14 \
	 fork10:15; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1165T$id: $tp OK ($ok)"
	else
		echo "*** C1165T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
