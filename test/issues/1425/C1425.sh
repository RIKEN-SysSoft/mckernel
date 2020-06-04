#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue="1425"
tid=01

STOPSIG_LIST="TSTP TTIN TTOU"

for signame in ${STOPSIG_LIST}
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sh ./check_stopsig.sh ${MCEXEC} ${signame}

	if [ $? -eq 0 ]; then
		echo "*** ${tname} PASSED ******************************"
	else
		echo "*** ${tname} FAILED ******************************"
	fi
	let tid++
	echo ""
done

for tp in kill01 kill02 kill06 kill07 kill08 kill09 signal01 signal03 signal04 signal05
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

