#/bin/sh

USELTP=1
USEOSTEST=0
MCREBOOT=0

. ../../common.sh

issue="1428"
tid=01

arch="`uname -p`"
if [ "${arch}" == "x86_64" ]; then
	UTI_TEST_DIR="../../uti"
elif [ "${arch}" == "aarch64" ]; then
	UTI_TEST_DIR="../../uti/arm64"
else
	echo "Error: ${arch} is unexpected arch"
	exit 1
fi

# make uti test
pushd ${UTI_TEST_DIR}
make
popd

mcreboot
for tno in `seq 12 20`
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo ${MCEXEC} --enable-uti ${UTI_TEST_DIR}/CT${tno} 2>&1 | tee ./${tname}.txt
	rc=$?
	ngs=`grep "NG" ./${tname}.txt | wc -l`

	if [ ${ngs} -eq 0 ]; then
		echo "*** ${tname} PASSED ******************************"
	else
		echo "*** ${tname} FAILED ******************************"
	fi
	let tid++
	echo ""
done

echo "*** Stop mckernel to exec CT31-33 on Linux"
mcstop
for tno in `seq 31 34`
do
	sudo ${UTI_TEST_DIR}/CT${tno} -l &> ./lnx_CT${tno}.txt
done

echo "*** Boot mckernel"
mcreboot
echo ""

for tno in `seq 31 34`
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo ${MCEXEC} --enable-uti ${UTI_TEST_DIR}/CT${tno} 2>&1 | tee ./${tname}.txt
	rc=$?
	ngs=`grep "NG" ./${tname}.txt | wc -l`
	echo "** Result on Linux **"
	grep "waiter" ./lnx_CT${tno}.txt

	if [ ${ngs} -eq 0 ]; then
		echo "*** ${tname} PASSED ******************************"
	else
		echo "*** ${tname} FAILED ******************************"
	fi
	let tid++
	echo ""
done

for tp in futex_wait01 futex_wait02 futex_wait03 futex_wait04 futex_wait_bitset01 futex_wait_bitset02 futex_wake01 futex_wake02 futex_wake03
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
