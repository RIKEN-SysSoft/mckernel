#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue="1399"
tid=01

for tno in 01
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo ${MCEXEC} ./C1399T${tno}

	if [ $? -eq 0 ]; then
		echo "*** ${tname} PASSED ******************************"
	else
		echo "*** ${tname} FAILED ******************************"
	fi
	let tid++
	echo ""
done

for tp in set_robust_list01 get_robust_list01
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep PASS $tp.txt | wc -l`
	ng=`grep FAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=$ng)"
	fi
	let tid++
	echo ""
done

