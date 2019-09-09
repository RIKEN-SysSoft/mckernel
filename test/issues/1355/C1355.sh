#/bin/sh

USELTP=0
USEOSTEST=0

issue=1355
tid=01

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"

grep "result=0" ./x86_64_intel_bench.txt

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"

grep "All processes entering MPI_Finalize" ./x86_64_pingpong.txt

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"

grep "result=0" ./aarch64_intel_bench.txt

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"

grep "All processes entering MPI_Finalize" ./aarch64_pingpong.txt

if [ $? -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ng=0

grep -e ".*apollo15.*rank 0.*" ./aarch64_mvapich.txt
if [ $? -ne 0 ]; then
	let ng++
fi
grep -e ".*apollo16.*rank 1.*" ./aarch64_mvapich.txt
if [ $? -ne 0 ]; then
	let ng++
fi

if [ $ng -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

