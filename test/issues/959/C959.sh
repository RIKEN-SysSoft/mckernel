#/bin/sh

USELTP=1
USEOSTEST=1

LTP_LIST="mbind01 get_mempolicy01"
OSTEST_MBIND_LIST="1 3 5 9 12 14 15 16 20 24 26 28 30"

BOOTPARAM="-c 1-7 -m 10G@0,10G@1 -O -e anon_on_demand"
. ../../common.sh

issue="959"
tid=01
arch=`uname -p`

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
sudo ${MCEXEC} ./check_mempol_il 1 30 6 3 3 3

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
sudo ${MCEXEC} ./check_mempol_il 2 30 6 3 3 3

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
sudo ${MCEXEC} ./check_mempol_il 1 30 6 2 0 6

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
sudo ${MCEXEC} ./check_mempol_il 2 30 6 2 0 6

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

BOOTPARAM="-c 1-7 -m 10G@0,2G@1 -O -e anon_on_demand"
mcstop
mcreboot

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
${IHKOSCTL} 0 clear_kmsg
sudo ${MCEXEC} ./check_mempol_il 1 30 6 2 4 2
ret=$?
dbg_prints=`${IHKOSCTL} 0 kmsg | grep "TEST_959" | wc -l`

if [ ${ret} -eq 0 -a ${dbg_prints} -gt 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
sudo ${MCEXEC} ./check_mempol_il 2 30 6 2 4 2
ret=$?
dbg_prints=`${IHKOSCTL} 0 kmsg | grep "TEST_959" | wc -l`

if [ ${ret} -eq 0 -a ${dbg_prints} -gt 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

for tp in ${LTP_LIST}
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

for tno in ${OSTEST_MBIND_LIST}
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	${MCEXEC} ${TESTMCK} -s mbind -n ${tno} -- -n 2 2>&1 | tee test_mck-mbind${tno}.txt
	if [ $? = 0 ]; then
		echo "*** ${tname} PASSED"
	else
		echo "*** ${tname} FAILED"
	fi
	let tid++
	echo ""
done
