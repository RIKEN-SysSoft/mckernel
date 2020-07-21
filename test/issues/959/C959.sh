#/bin/sh

USELTP=1
USEOSTEST=0

BOOTPARAM="-c 1-7 -m 10G@0,10G@1 -O -e anon_on_demand"
. ../../common.sh

issue="959"
tid=01

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
sudo ${MCEXEC} ./check_mempol_il 1 30 6 2 4 2

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
sudo ${MCEXEC} ./check_mempol_il 2 30 6 2 4 2

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

for tp in mbind01
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

