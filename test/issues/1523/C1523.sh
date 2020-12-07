#/bin/sh

USELTP=1
USEOSTEST=0

MCREBOOT=0
. ../../common.sh

BOOTPARAM="${BOOTPARAM} -e anon_on_demand"
mcreboot

issue="1523"
tid=01

for tp in move_pages01 move_pages02 move_pages04 move_pages06 move_pages09 move_pages10
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

