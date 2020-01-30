#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue="1383"
tid=01

arch=`uname -p`
if [ "$arch" == "x86_64" ]; then
	pgshift=21
elif [ "$arch" == "aarch64" ]; then
	pgshift=29
fi

for tno in 01
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo ${MCEXEC} ./C1383T${tno} ${pgshift}

	if [ $? -eq 0 ]; then
		echo "*** ${tname} PASSED ******************************"
	else
		echo "*** ${tname} FAILED ******************************"
	fi
	let tid++
	echo ""
done

for tp in thp02 mremap01 mremap02 mremap03 mremap04 mremap05 move_pages10
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

