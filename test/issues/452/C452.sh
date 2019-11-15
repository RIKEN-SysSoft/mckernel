#!/bin/sh
USELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
$MCEXEC ./C452T01

for i in mmap01:02 mmap02:03 mmap03:04 mmap04:05 mmap12:06 brk01:07 fork01:08 \
	 fork02:09 fork03:10 mremap04:11 mremap05:12 munmap01:13 shmat01:14 \
	 shmdt01:15 mlock01:16 mlock04:17 execve01:18 exit01:19 exit02:20 \
	 exit_group01:21 mprotect02:22 mprotect03:23 msync01:24 msync02:25 \
	 munlock01:26 remap_file_pages01:27 remap_file_pages01:28; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo PATH=$PATH:$LTPBIN $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C452T$id: $tp PASS ($ok)"
	else
		echo "*** C452T$id: $tp FAIL (ok=$ok ng=%ng)"
	fi
done
