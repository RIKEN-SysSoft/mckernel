#!/bin/sh
USELTP=1
USEOSTEST=0
USESTRESSTEST=1
MCREBOOT=0
MCSTOP=0

. ../../common.sh

################################################################################
ng=0
for i in {1..60}; do
	if ! $MCEXEC $LTPBIN/futex_wait_bitset02; then
		ng=1
		break
	fi
	if [ $i != 60 ]; then
		sleep 60
	fi
done
if [ $ng = 0 ]; then
	echo "*** C1186T01: OK"
else
	echo "*** C1186T01: NG"
fi

$MCEXEC ./C1186

for i in gettimeofday01:03 gettimeofday02:04 time01:05 time02:06 \
	 clock_nanosleep01:07 clock_nanosleep2_01:08 sigtimedwait01:09; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1186T$id: $tp OK ($ok)"
	else
		echo "*** C1186T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
