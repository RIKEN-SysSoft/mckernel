#!/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

tid=001
echo "*** CT$tid start *******************************"
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
echo ""

tid=002
echo "*** CT$tid start *******************************"
executable=`readlink -f ./print_maps`
interp=`readelf -a ./print_maps | grep "interpreter:" | grep -o "/.*$"`
interp=${interp%\]}
interp=`readlink -f ${interp}`
${MCEXEC} ./print_maps 2>&1 | tee ./CT${tid}.txt
grep "${executable}" ./CT${tid}.txt &> /dev/null
if [ $? -eq 0 ]; then
	echo "[OK] ${executable} is found in maps"
else
	echo "[NG] ${executable} is NOT found in maps"
fi
grep "${interp}" ./CT${tid}.txt &> /dev/null
if [ $? -eq 0 ]; then
	echo "[OK] ${interp} is found in maps"
else
	echo "[NG] ${interp} is NOT found in maps"
fi
echo ""

tid=003
echo "*** CT$tid start *******************************"
${MCEXEC} ./static_print_maps
if [ $? -eq 0 ]; then
	echo "[OK] exec static link program"
else
	echo "[NG] exec static link program"
fi
echo ""

tid=004
echo "*** CT$tid start *******************************"
${MCEXEC} sh ./hello.sh
if [ $? -eq 0 ]; then
	echo "[OK] exec shell script"
else
	echo "[NG] exec shell script"
fi
echo ""

tid=005
echo "*** CT$tid start *******************************"
${MCEXEC} ./fork_execve ./print_maps
if [ $? -eq 0 ]; then
	echo "[OK] fork and exec"
else
	echo "[NG] fork and exec"
fi
echo ""

tid=006
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork01 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=007
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork02 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=008
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork03 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=009
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork04 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=010
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork07 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=011
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork08 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=012
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork09 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=013
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork10 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=014
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/fork11 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=015
echo "*** CT$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve01 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=016
echo "*** CT$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve02 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=017
echo "*** CT$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve03 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

tid=018
echo "*** CT$tid start *******************************"
sudo PATH=${LTPBIN}:${PATH} ${MCEXEC} ${LTPBIN}/execve05 20 ${LTPBIN}/execve05 ${LTPBIN}/execve05 4 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
echo ""

