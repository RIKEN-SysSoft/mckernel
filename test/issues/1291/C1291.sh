#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue=1291
tid=01

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
tp=mmap13
sudo $MCEXEC $LTPBIN/${tp} 2>&1 | tee $tp.txt
ok=`grep TPASS $tp.txt | wc -l`
ng=`grep TFAIL $tp.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** ${tname} PASSED ($ok)"
else
	echo "*** ${tname} FAILED (ok=$ok ng=%ng)"
fi
let tid++
echo ""

for devf in /dev/mem /dev/zero
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	if [ ! -e $devf ]; then
		echo "$devf is not exist"
		echo "*** ${tname} SKIP"
		let tid++
		echo ""
		continue
	fi
	sudo $MCEXEC ./map_and_read ${devf}
	if [ $? = 0 ]; then
		echo "*** ${tname} PASSED"
	else
		echo "*** ${tname} FAILED"
	fi
	let tid++
	echo ""
done

for tp in mmap01 mmap02 mmap03 mmap04 mmap05 mmap06 mmap07 mmap08 \
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

