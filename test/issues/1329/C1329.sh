#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue="1329"
tid=01

if [ `uname -p` == "x86_64" ]; then
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	for idx in `seq 1 300`;
	do
		echo "*** Rep: $idx ***"
		echo -n "** Start:"
		date "+%H:%M:%S"

		sudo $MCEXEC $LTPBIN/msgctl11
		echo -n "** Done:"
		date "+%H:%M:%S"
	done
	echo "*** ${tname} PASSED"
fi
let tid++

for tp in fork01 fork02 fork03 fork04 fork05 fork06 fork07 fork08 fork09 fork10 fork11
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep PASS $tp.txt | wc -l`
	ng=`grep FAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=%ng)"
	fi
	let tid++
	echo ""
done

