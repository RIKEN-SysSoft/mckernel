#!/bin/sh
USELTP=0
USEOSTEST=0

BOOTPARAM="-c 1-7 -m 4G@0"
. ../../common.sh

if ! sudo ls /sys/kernel/debug | grep kmemleak > /dev/null 2>&1; then
	echo kmemleak: not found >&2
	exit 1
fi

dd if=/dev/zero of=rpf.data bs=1M count=1024
sync

echo 'C840T01... '
b=
while [ x$b = x ]; do
	ng=0
	sync
	sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
	sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
	sudo $SBINDIR/mcreboot.sh $BOOTPARAM
	$SBINDIR/ihkosctl 0 clear_kmsg
	sudo dmesg -c > /dev/null
	$MCEXEC ./C840T01
	sleep 3
	rpf=`dmesg | grep 'remote_page_fault:interrupted. -512'`
	offload=` $SBINDIR/ihkosctl 0 kmsg | grep 'is dead, terminate()'`
	sudo $SBINDIR/mcstop+release.sh
	sudo sh -c 'echo scan > /sys/kernel/debug/kmemleak'
	if [ x"$rpf" = x ]; then
		echo '*** C840T01: WARN (remote_page_fault)'
		ng=1
	elif [ x"$offload" = x ]; then
		echo '*** C840T01: WARN (syscall offloading)'
		ng=1
	elif sudo cat /sys/kernel/debug/kmemleak | tee C840T01.kmemleak | grep 'mcctrl'; then
		echo '*** C840T01: NG (kmemleak)'
		ng=1
		b=1
	fi
	if [ $ng = 0 ]; then
		echo '*** C840T01: OK'
		b=1
	fi
done

echo 'C840T02... '
b=
while [ x$b = x ]; do
	ng=0
	sync
	sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
	sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
	sudo $SBINDIR/mcreboot.sh $BOOTPARAM
	$SBINDIR/ihkosctl 0 clear_kmsg
	sudo dmesg -c > /dev/null
	$MCEXEC ./C840T02
	sleep 3
	rpf=`dmesg | grep 'remote_page_fault:interrupted. -512'`
	offload=` $SBINDIR/ihkosctl 0 kmsg | grep 'is dead, terminate()'`
	sudo $SBINDIR/mcstop+release.sh
	sudo sh -c 'echo scan > /sys/kernel/debug/kmemleak'
	if [ x"$rpf" != x ]; then
		echo '*** C840T02: WARN (remote_page_fault)'
		ng=1
	elif [ x"$offload" = x ]; then
		echo '*** C840T02: WARN (syscall offloading)'
		ng=1
	elif sudo cat /sys/kernel/debug/kmemleak | tee C840T02.kmemleak | grep 'mcctrl'; then
		echo '*** C840T02: NG (kmemleak)'
		ng=1
		b=1
	fi
	if [ $ng = 0 ]; then
		echo '*** C840T02: OK'
		b=1
	fi
done

echo 'C840T03... '
b=
while [ x$b = x ]; do
	ng=0
	sync
	sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
	sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
	sudo $SBINDIR/mcreboot.sh $BOOTPARAM
	$SBINDIR/ihkosctl 0 clear_kmsg
	sudo dmesg -c > /dev/null
	$MCEXEC ./C840T03
	sleep 3
	rpf=`dmesg | grep 'remote_page_fault:interrupted. -512'`
	offload=` $SBINDIR/ihkosctl 0 kmsg | grep 'is dead, terminate()'`
	sudo $SBINDIR/mcstop+release.sh
	sudo sh -c 'echo scan > /sys/kernel/debug/kmemleak'
	if [ x"$rpf" != x ]; then
		echo '*** C840T03: WARN (remote_page_fault)'
		ng=1
	elif [ x"$offload" != x ]; then
		echo '*** C840T03: WARN (syscall offloading)'
		ng=1
	elif sudo cat /sys/kernel/debug/kmemleak | tee C840T03.kmemleak | grep 'mcctrl'; then
		echo '*** C840T03: NG (kmemleak)'
		ng=1
		b=1
	fi
	if [ $ng = 0 ]; then
		echo '*** C840T03: OK'
		b=1
	fi
done

echo 'C840T04... '
b=
while [ x$b = x ]; do
	ng=0
	sync
	sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
	sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
	sudo $SBINDIR/mcreboot.sh $BOOTPARAM
	$SBINDIR/ihkosctl 0 clear_kmsg
	sudo dmesg -c > /dev/null
	timeout -s 9 2 $MCEXEC ./C840T04
	sleep 3
	rpf=`dmesg | grep 'remote_page_fault:interrupted. -512'`
	offload=` $SBINDIR/ihkosctl 0 kmsg | grep 'is dead, terminate()'`
	sudo $SBINDIR/mcstop+release.sh
	sudo sh -c 'echo scan > /sys/kernel/debug/kmemleak'
	if [ x"$rpf" = x ]; then
		echo '*** C840T04: WARN (remote_page_fault)'
		ng=1
	elif [ x"$offload" = x ]; then
		echo '*** C840T04: WARN (syscall offloading)'
		ng=1
	elif sudo cat /sys/kernel/debug/kmemleak | tee C840T04.kmemleak | grep 'mcctrl'; then
		echo '*** C840T04: NG (kmemleak)'
		ng=1
		b=1
	fi
	if [ $ng = 0 ]; then
		echo '*** C840T04: OK'
		b=1
	fi
done

echo 'C840T05... '
b=
while [ x$b = x ]; do
	ng=0
	sync
	sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
	sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
	sudo $SBINDIR/mcreboot.sh $BOOTPARAM
	$SBINDIR/ihkosctl 0 clear_kmsg
	sudo dmesg -c > /dev/null
	timeout -s 9 2 $MCEXEC ./C840T05
	sleep 3
	rpf=`dmesg | grep 'remote_page_fault:interrupted. -512'`
	offload=` $SBINDIR/ihkosctl 0 kmsg | grep 'is dead, terminate()'`
	sudo $SBINDIR/mcstop+release.sh
	sudo sh -c 'echo scan > /sys/kernel/debug/kmemleak'
	if [ x"$rpf" != x ]; then
		echo '*** C840T05: WARN (remote_page_fault)'
		ng=1
	elif [ x"$offload" = x ]; then
		echo '*** C840T05: WARN (syscall offloading)'
		ng=1
	elif sudo cat /sys/kernel/debug/kmemleak | tee C840T05.kmemleak | grep 'mcctrl'; then
		echo '*** C840T05: NG (kmemleak)'
		ng=1
		b=1
	fi
	if [ $ng = 0 ]; then
		echo '*** C840T05: OK'
		b=1
	fi
done

echo 'C840T06... '
b=
while [ x$b = x ]; do
	ng=0
	sync
	sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
	sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
	sudo $SBINDIR/mcreboot.sh $BOOTPARAM
	$SBINDIR/ihkosctl 0 clear_kmsg
	sudo dmesg -c > /dev/null
	timeout -s 9 2 $MCEXEC ./C840T06
	sleep 3
	rpf=`dmesg | grep 'remote_page_fault:interrupted. -512'`
	offload=` $SBINDIR/ihkosctl 0 kmsg | grep 'is dead, terminate()'`
	sudo $SBINDIR/mcstop+release.sh
	sudo sh -c 'echo scan > /sys/kernel/debug/kmemleak'
	if [ x"$rpf" != x ]; then
		echo '*** C840T06: WARN (remote_page_fault)'
		ng=1
	elif [ x"$offload" != x ]; then
		echo '*** C840T06: WARN (syscall offloading)'
		ng=1
	elif sudo cat /sys/kernel/debug/kmemleak | tee C840T06.kmemleak | grep 'mcctrl'; then
		echo '*** C840T06: NG (kmemleak)'
		ng=1
		b=1
	fi
	if [ $ng = 0 ]; then
		echo '*** C840T06: OK'
		b=1
	fi
done

rm -f rpf.data rpf.out
