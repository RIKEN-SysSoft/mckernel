#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

PWD=`pwd`
LTPLIST="${PWD}/ltp_list"
issue="1511"
tid=01

ulimit -S -c unlimited

for tp in oom02
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	echo "test process exit"
	echo "*** ${tname} PASSED"
	let tid++
	echo ""
done

while read tp
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
done < ${LTPLIST}
