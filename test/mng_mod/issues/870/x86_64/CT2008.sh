#!/bin/sh
MCEXEC=mcexec
dd if=/dev/zero of=testfile bs=$((1024 * 1024)) count=$((2 * 1024))
sync
sudo /sbin/sysctl vm.drop_caches=3
./CT2000 ./CT2008
rm -f testfile
