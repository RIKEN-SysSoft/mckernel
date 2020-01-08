#/bin/sh

USELTP=0
USEOSTEST=0

. ../../common.sh

issue="929"
tid=01

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
TEST_CMD="mpirun -f ./hostfile -ppn 5 ${MCEXEC} -n 5 ./test_prog.sh"
echo ${TEST_CMD}
${TEST_CMD} &> ${tname}.txt
mpi_ret=$?

cat ./${tname}.txt
started_num=`grep 'test_prog is started' ./${tname}.txt | wc -l`

if [ ${mpi_ret} -eq 0 -a ${started_num} -eq 5 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
TEST_CMD="mpirun -f ./hostfile -ppn 5 ${MCEXEC} -n 3 ./test_prog.sh"
echo ${TEST_CMD}
${TEST_CMD} &> ${tname}.txt
mpi_ret=$?

cat ./${tname}.txt
started_num=`grep 'test_prog is started' ./${tname}.txt | wc -l`

if [ ${mpi_ret} -ne 0 -a ${started_num} -eq 3 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
TEST_CMD="mpirun -f ./hostfile -ppn 3 ${MCEXEC} -n 5 ./test_prog.sh"
echo ${TEST_CMD}
${TEST_CMD} &> ${tname}.txt
mpi_ret=$?

cat ./${tname}.txt
started_num=`grep 'test_prog is started' ./${tname}.txt | wc -l`

if [ ${mpi_ret} -ne 0 -a ${started_num} -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
TEST_CMD="mpirun -f ./hostfile -ppn 6 ${MCEXEC} -n 3 ./test_prog.sh"
echo ${TEST_CMD}
${TEST_CMD} &> ${tname}.txt
mpi_ret=$?

cat ./${tname}.txt
started_num=`grep 'test_prog is started' ./${tname}.txt | wc -l`

if [ ${mpi_ret} -ne 0 -a ${started_num} -eq 3 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
TEST_CMD="mpirun -f ./hostfile -ppn 250 ${MCEXEC} -n 250 ./test_prog.sh"
echo ${TEST_CMD}
${TEST_CMD} &> ${tname}.txt
mpi_ret=$?

head -n 10 ./${tname}.txt
echo "..."
started_num=`grep 'test_prog is started' ./${tname}.txt | wc -l`

if [ ${mpi_ret} -ne 0 -a ${started_num} -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ng=0
TEST_CMD="mpirun -f ./hostfile -ppn 5 ${MCEXEC} -n 5 ./test_prog.sh"
echo "** reboot mcrernel for check pe_list_len"
mcreboot
echo "** enable debug message in mcexec_get_cpuset"
sudo sh -c "echo -n 'func mcexec_get_cpuset +p' > /sys/kernel/debug/dynamic_debug/control"
echo ${TEST_CMD}
for i in `seq 1 20`
do
	${TEST_CMD} &> ${tname}.txt
	mpi_ret=$?
	started_num=`grep 'test_prog is started' ./${tname}.txt | wc -l`
	if [ ${mpi_ret} -eq 0 -a ${started_num} -eq 5 ]; then
		echo "[OK] exec: $i"
	else
		echo "[NG] exec: $i"
		let ng++
	fi
done
echo "** check pe_list_len"
dmesg --notime | grep "mcexec_get_cpuset: pe_list" | tail -n 20 | cut -f 2-3 -d ':' > ./pe_list_len.txt
cat ./pe_list_len.txt | while read line
do
	len=`echo ${line} | cut -f 2 -d ':'`
	if [ ${len} -ge 0 -a ${len} -le 5 ]; then
		echo "[OK] ${line}"
	else
		echo "[NG] ${line}"
		let ng++
	fi
done
echo "** disable debug message in mcexec_get_cpuset"
sudo sh -c "echo -n 'func mcexec_get_cpuset -p' > /sys/kernel/debug/dynamic_debug/control"

if [ ${ng} -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

