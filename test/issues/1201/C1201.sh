#!/bin/sh
USELTP=1
USEOSTEST=0
MCREBOOT=0
MCSTOP=0
STRESSTESTDIR=

. ../../common.sh

################################################################################
if [ "X$STRESSTESTDIR" = X ]; then
	if [ -x "$HOME/stress_test/bin/signalonfork" ]; then
		STRESSTESTDIR="$HOME/stress_test"
	else
		echo No stress test dir >&2
		exit 1
	fi
fi
if [ ! -x "$STRESSTESTDIR/bin/signalonfork" ]; then
	echo No stress test dir >&2
	exit 1
fi

ng=0
org="`pwd`"
(
	cd "$STRESSTESTDIR/bin"
	rm -f config.sh.bak
	if [ -f config.sh ]; then
		mv config.sh config.sh.bak
		sed -e '/^MCKDIR=/d' config.sh.bak > config.sh
	fi
	echo "MCKDIR=\"$MCK_DIR\"" >> config.sh
	if ! grep ^MCREBOOTOPTION= config.sh > /dev/null 2>&1; then
		echo "MCREBOOTOPTION=\"$BOOTPARAM\"" >> config.sh
	fi
	rm -f "$org/C1201T01.log"
	echo C1201T01 START
	for i in {1..100}; do
		sudo ./mck-stop.sh >> "$org/C1201T01.log" 2>&1
		sudo ./mck-boot.sh >> "$org/C1201T01.log" 2>&1
		./mck-mcexec.sh ./killit -np 8 -t 2000 - ./signalonfork \
				-nosignal >> "$org/C1201T01.log" 2>&1
		if [ "X$?" = X0 ]; then
			echo -n .
		else
			echo
			echo C1201T01: NG see C1201T01.log
			ng=1
			break
		fi
	done
	if [ $ng = 0 ]; then
		echo
		echo C1201T01: OK
	fi
	if [ -f config.sh.bak ]; then
		mv config.sh.bak config.sh
	fi
)

for i in fork01:02 fork02:03 fork03:04 fork04:05 fork07:06 fork08:07 fork09:08 \
	 fork10:09 fork11:10; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1201T$id: $tp OK ($ok)"
	else
		echo "*** C1201T$id: $tp NG (ok=$ok ng=%ng)"
	fi
done
