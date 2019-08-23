#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue=1351
tid=01

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ng=0
${IHKOSCTL} 0 clear_kmsg
${MCEXEC} ./C1351

${IHKOSCTL} 0 kmsg | tee ./${tname}.txt

line=`grep -e "attr: 0x20731000" ./${tname}.txt | wc -l`

if [ ${line} -eq 3 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

for tp in madvise01 madvise02 madvise03 madvise04
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	$MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
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

