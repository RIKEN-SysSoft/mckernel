#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue=988
tid=01

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ng=0
${MCEXEC} ./C988

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

for tp in mmap01 mmap02 mmap03 mmap04 mmap05 mmap06 mmap07 mmap08\
	mmap09 mmap12 mmap14 mmap15
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

