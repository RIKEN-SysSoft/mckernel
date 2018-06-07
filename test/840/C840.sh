#!/bin/sh
if ! sudo ls /sys/kernel/debug | grep kmemleak > /dev/null 2>&1; then
	echo kmemleak: not found >&2
	exit 1
fi

echo 'C840T01... '
ng=0
sync
sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
./ihkosctl 0 clear_kmsg
sudo dmesg -c > /dev/null
sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
./mcexec ./C840T01
if [ `sudo cat /sys/kernel/debug/kmemleak | wc -l` != 0 ]; then
	echo 'C840T01: NG (kmemleak)'
	ng=1
fi
if ! dmesg | grep 'remote_page_fault:interrupted. -512' > /dev/null 2>&1; then
	echo 'C840T01: WARN (remote_page_fault)'
	ng=1
fi
if ! ./ihkosctl 0 kmsg | grep 'is dead, terminate()' > /dev/null 2>&1; then
	echo 'C840T01: WARN (syscall offloading)'
	ng=1
fi
if [ $ng = 0 ]; then
	echo C840T01: OK
fi

echo 'C840T02... '
ng=0
sync
sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
./ihkosctl 0 clear_kmsg
sudo dmesg -c > /dev/null
sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
./mcexec ./C840T02
if [ `sudo cat /sys/kernel/debug/kmemleak | wc -l` != 0 ]; then
	echo 'C840T02: NG (kmemleak)'
	ng=1
fi
if dmesg | grep 'remote_page_fault:interrupted. -512' > /dev/null 2>&1; then
	echo 'C840T02: WARN (remote_page_fault)'
	ng=1
fi
if ! ./ihkosctl 0 kmsg | grep 'is dead, terminate()' > /dev/null 2>&1; then
	echo 'C840T02: WARN (syscall offloading)'
	ng=1
fi
if [ $ng = 0 ]; then
	echo C840T02: OK
fi

echo 'C840T03... '
ng=0
sync
sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
./ihkosctl 0 clear_kmsg
sudo dmesg -c > /dev/null
sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
./mcexec ./C840T03
if [ `sudo cat /sys/kernel/debug/kmemleak | wc -l` != 0 ]; then
	echo 'C840T03: NG (kmemleak)'
	ng=1
fi
if dmesg | grep 'remote_page_fault:interrupted. -512' > /dev/null 2>&1; then
	echo 'C840T03: WARN (remote_page_fault)'
	ng=1
fi
if ./ihkosctl 0 kmsg | grep 'is dead, terminate()' > /dev/null 2>&1; then
	echo 'C840T03: WARN (syscall offloading)'
	ng=1
fi
if [ $ng = 0 ]; then
	echo C840T03: OK
fi

echo 'C840T04... '
ng=0
sync
sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
./ihkosctl 0 clear_kmsg
sudo dmesg -c > /dev/null
sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
timeout -s 9 2 ./mcexec ./C840T04
sleep 2
if [ `sudo cat /sys/kernel/debug/kmemleak | wc -l` != 0 ]; then
	echo 'C840T04: NG (kmemleak)'
	ng=1
fi
if ! dmesg | grep 'remote_page_fault:interrupted. -512' > /dev/null 2>&1; then
	echo 'C840T04: WARN (remote_page_fault)'
	ng=1
fi
if ! ./ihkosctl 0 kmsg | grep 'is dead, terminate()' > /dev/null 2>&1; then
	echo 'C840T04: WARN (syscall offloading)'
	ng=1
fi
if [ $ng = 0 ]; then
	echo C840T04: OK
fi

echo 'C840T05... '
ng=0
sync
sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
./ihkosctl 0 clear_kmsg
sudo dmesg -c > /dev/null
sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
timeout -s 9 2 ./mcexec ./C840T05
sleep 2
if [ `sudo cat /sys/kernel/debug/kmemleak | wc -l` != 0 ]; then
	echo 'C840T05: NG (kmemleak)'
	ng=1
fi
if dmesg | grep 'remote_page_fault:interrupted. -512' > /dev/null 2>&1; then
	echo 'C840T05: WARN (remote_page_fault)'
	ng=1
fi
if ! ./ihkosctl 0 kmsg | grep 'is dead, terminate()' > /dev/null 2>&1; then
	echo 'C840T05: WARN (syscall offloading)'
	ng=1
fi
if [ $ng = 0 ]; then
	echo C840T05: OK
fi

echo 'C840T06... '
ng=0
sync
sudo /sbin/sysctl vm.drop_caches=3 > /dev/null 2>&1
./ihkosctl 0 clear_kmsg
sudo dmesg -c > /dev/null
sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
timeout -s 9 2 ./mcexec ./C840T06
sleep 2
if [ `sudo cat /sys/kernel/debug/kmemleak | wc -l` != 0 ]; then
	echo 'C840T06: NG (kmemleak)'
	ng=1
fi
if dmesg | grep 'remote_page_fault:interrupted. -512' > /dev/null 2>&1; then
	echo 'C840T06: WARN (remote_page_fault)'
	ng=1
fi
if ./ihkosctl 0 kmsg | grep 'is dead, terminate()' > /dev/null 2>&1; then
	echo 'C840T06: WARN (syscall offloading)'
	ng=1
fi
if [ $ng = 0 ]; then
	echo C840T06: OK
fi
