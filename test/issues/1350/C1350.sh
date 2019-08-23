#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue=1350
tid=01

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
${MCEXEC} ./C1350

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

for tp in rt_sigsuspend01 sigsuspend01 pause01 pause02 pause03
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=%ng)"
	fi
	let tid++
	echo ""
done

