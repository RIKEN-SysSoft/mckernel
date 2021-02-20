#/bin/sh

USELTP=1
USEOSTEST=1

. ../../common.sh

PWD=`pwd`
LTPLIST="${PWD}/ltp_list"

issue="1511"
tid=01

for tp in oom02
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

for tno in `seq 0 2`
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo $MCEXEC ${TESTMCK} -s page_fault_forwording -n ${tno} 2>&1 | tee pf-${tno}.txt
	grep "RESULT: ok" pf-${tno}.txt
	if [ $? -eq 0 ]; then
		echo "*** ${tname} PASSED"
	else
		echo "*** ${tname} FAILED"
	fi
	let tid++
	echo ""
done

