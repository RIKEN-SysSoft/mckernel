#!/bin/sh

USELTP=1
USEOSTEST=0

# To make oversubscribe happen
BOOTPARAM="-c 1-4 -m 10G@0 -O"
. ../../common.sh

issue=1113
tid=001

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
echo "[MPI's machine file]"
cat ./machinefile
echo "**"
for ppn in 8 32 64 128
do
	mpiexec -f ./machinefile -ppn ${ppn} ${MCEXEC} ./hello quiet
	if [ $? -eq 0 ]; then
		echo "[OK] ppn ${ppn}"
	else
		echo "[NG] ppn ${ppn}"
	fi
	sleep 1
done
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
executable=`readlink -f ./print_maps`
interp=`readelf -a ./print_maps | grep "interpreter:" | grep -o "/.*$"`
interp=${interp%\]}
interp=`readlink -f ${interp}`
${MCEXEC} ./print_maps 2>&1 | tee ./${tname}.txt
grep "${executable}" ./${tname}.txt &> /dev/null
if [ $? -eq 0 ]; then
	echo "[OK] ${executable} is found in maps"
else
	echo "[NG] ${executable} is NOT found in maps"
fi
grep "${interp}" ./${tname}.txt &> /dev/null
if [ $? -eq 0 ]; then
	echo "[OK] ${interp} is found in maps"
else
	echo "[NG] ${interp} is NOT found in maps"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
${MCEXEC} ./static_print_maps
if [ $? -eq 0 ]; then
	echo "[OK] exec static link program"
else
	echo "[NG] exec static link program"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
${MCEXEC} sh ./hello.sh
if [ $? -eq 0 ]; then
	echo "[OK] exec shell script"
else
	echo "[NG] exec shell script"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
${MCEXEC} ./fork_execve ./print_maps
if [ $? -eq 0 ]; then
	echo "[OK] fork and exec"
else
	echo "[NG] fork and exec"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
{ sh ./repeat.sh ${MCEXEC} ./check_data_area 10 & \
sh ./repeat.sh ${MCEXEC} ./check_data_area 20 & \
sh ./repeat.sh ${MCEXEC} ./check_data_area 30 & \
wait; } > CT${tid}.txt
ok=`grep '\[ OK \]' CT${tid}.txt | wc -l`
ng=`grep '\[ NG \]' CT${tid}.txt | wc -l`
echo " parallel exec same executable: ok:${ok} ng:${ng}"
if [ $ng = 0 ] && [ $ok -eq 300 ]; then
	echo "*** ${tname}: PASSED"
else
	echo "*** ${tname}: FAILED"
fi
let tid++
echo""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
sudo HUGETLB_VERBOSE=2 HUGETLB_ELFMAP=RW HUGETLB_DEBUG=1 ${MCEXEC} ./bigbssdata 2>&1 | tee ./${tname}.txt
grep "libhugetlbfs.tmp" ./${tname}.txt &> /dev/null
if [ $? -eq 0 ]; then
	echo "[OK] libhugetlbfs is working"
else
	echo "[NG] libhugetlbfs is NOT working"
fi
let tid++
echo ""

cp ${LTPBIN}/execve_child ./
for tp in fork01 fork02 fork03 fork04 fork07 fork08 fork09 fork10 fork11 execve01 execve02 execve03 execve05
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo PATH=${LTPBIN}:${PATH} $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
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

