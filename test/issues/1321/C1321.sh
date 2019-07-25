#!/bin/sh
USELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
for i in fork01:01 fork02:02 fork03:03 exit01:04 exit02:05 exit_group01:06 \
         wait401:07 waitpid01:08 waitpid02:09 waitpid03:10; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	$IHKOSCTL 0 clear_kmsg
	$MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	err=`$IHKOSCTL 0 kmsg | grep fileobj_free | wc -l`
	if [ $err != 0 ]; then
		echo "--- C1321T$id: error"
		$IHKOSCTL 0 kmsg | grep fileobj_free
		ng=$((ng + 1))
	else
		echo "--- C1321T$id: no error"
	fi
	if [ $ng = 0 ]; then
		echo "*** C1321T$id: $tp PASS ($ok)"
	else
		echo "*** C1321T$id: $tp FAIL (ok=$ok ng=%ng)"
	fi
done
