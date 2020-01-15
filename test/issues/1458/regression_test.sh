#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

for tp in shmat01 shmat02 shmat03 shmctl01 shmctl02 shmctl03 shmctl04 shmdt01 shmdt02 shmget01 shmget02 shmget03 shmget04 shmget05
do
	tname=`printf "" ${tid}`
	echo "*** LTP-${tp} start *******************************"
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.ltplog
	ok=`grep PASS $tp.ltplog | wc -l`
	ng=`grep FAIL $tp.ltplog | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=$ng)"
	fi
	echo ""
done
