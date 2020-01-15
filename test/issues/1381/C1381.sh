#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue="1381"
tid=01

for tp in shmat01 shmat02 shmat03 shmctl01 shmctl02 shmctl03 shmctl04 shmdt01 shmdt02 shmget01 shmget02 shmget03 shmget04 shmget05
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

