#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue=1354
tid=01

for tp in futex_wait01 futex_wait02 futex_wait03 futex_wait04 \
	futex_wait_bitset01 futex_wait_bitset02 \
	futex_wake01 futex_wake02 futex_wake03
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	${IHKOSCTL} 0 clear_kmsg

	$MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng1=`grep TFAIL $tp.txt | wc -l`
	ng2=`${IHKOSCTL} 0 kmsg | grep NOT_FIXED | wc -l`
	if [ $ng1 = 0 -a $ng2 = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng1=$ng1 ng2=$ng2)"
	fi
	let tid++
	echo ""
done

