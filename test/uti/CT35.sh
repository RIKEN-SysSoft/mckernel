#!/usr/bin/bash

mck_dir=/work/gg10/e29005/project/os/install
nloop=800
exe=CT26
mck=1

mcexec="${mck_dir}/bin/mcexec"

sudo ${mck_dir}/sbin/mcstop+release.sh
sudo ${mck_dir}/sbin/mcreboot.sh -c 1,2,3 -m 512M

ulimit -c unlimited

for((count=0;count<nloop;count++)); do
    if [ $mck -eq 1 ]; then
	export MCKERNEL_LD_PRELOAD=./preloadlib.so
	#    $mcexec --enable-uti ./$exe
#	$mcexec gdb -batch -ex "run" -ex "bt" ./$exe
	$mcexec ./$exe
    else
	export LD_PRELOAD=./preloadlib.so
	./$exe
    fi

    rc=$?
    if [ $rc -ne 0 ]; then
	echo mcexec returned $rc
	exit
    fi

    echo =====
    echo $count
    echo =====
    
done
