#!/bin/sh

USELTP=1
USEOSTEST=0

arch=`uname -p`
if [ -f "./${arch}_config" ]; then
	. ./${arch}_config
else
	echo "$1 is unexpected arch"
	exit 1
fi

. ../../common.sh

issue=1183
tid=01
ng=0
echo "*** C${issue}T${tid} start *******************************"
echo "** over-mapping with MAP_HUGETLB (expect mmap FAIL)"
for pgshift in ${PGSHIFT_LIST[@]}
do
	echo pageshift: ${pgshift}
	${MCEXEC} ./hugemap ${OVERSIZE} ${OVERSIZE} ${pgshift}

	if [ $? -ne 0 ]; then
		echo "** [OK]"
	else
		echo "** [NG]"
		ng=1
	fi
done
if [ ${ng} -eq 0 ]; then
	echo "*** C${issue}T${tid}: PASSED"
else
	echo "*** C${issue}T${tid}: FAILED"
fi
echo ""

tid=02
ng=0
echo "*** C${issue}T${tid} start *******************************"
echo "** within-mapping with MAP_HUGETLB (expect mmap SUCCESS)"
for pgshift in ${PGSHIFT_LIST[@]}
do
	echo pageshift: ${pgshift}
	${MCEXEC} ./hugemap ${INSIZE} ${INSIZE} ${pgshift}

	if [ $? -eq 0 ]; then
		echo "** [OK]"
	else
		echo "** [NG]"
		ng=1
	fi
done
if [ ${ng} -eq 0 ]; then
	echo "*** C${issue}T${tid}: PASSED"
else
	echo "*** C${issue}T${tid}: FAILED"
fi
echo ""

tid=03
ng=0
idx=0
echo "*** C${issue}T${tid} start *******************************"
echo "** multi within-mapping with MAP_HUGETLB"
for pgshift in ${PGSHIFT_LIST[@]}
do
	echo pageshift: ${pgshift}
	${MCEXEC} ./hugemap `expr ${MEMALL} \* 4` ${INSIZE} ${pgshift}

	if [ $? -eq ${MULTI_MAP_RESULT[${idx}]} ]; then
		echo "** [OK]"
	else
		echo "** [NG]"
		ng=1
	fi
	let idx++
done
if [ ${ng} -eq 0 ]; then
	echo "*** C${issue}T${tid}: PASSED"
else
	echo "*** C${issue}T${tid}: FAILED"
fi
echo ""

tid=04
ng=0
echo "*** C${issue}T${tid} start *******************************"
echo "** over-mapping without MAP_HUGETLB (expect mmap SUCCESS)"
${MCEXEC} ./hugemap ${OVERSIZE} ${OVERSIZE} -1

if [ $? -eq 0 ]; then
	echo "** [OK]"
else
	echo "** [NG]"
	ng=1
fi
if [ ${ng} -eq 0 ]; then
	echo "*** C${issue}T${tid}: PASSED"
else
	echo "*** C${issue}T${tid}: FAILED"
fi
echo ""

tid=05
ng=0
echo "*** C${issue}T${tid} start *******************************"
echo "** within-mapping without MAP_HUGETLB (expect mmap SUCCESS)"
${MCEXEC} ./hugemap ${INSIZE} ${INSIZE} -1

if [ $? -eq 0 ]; then
	echo "** [OK]"
else
	echo "** [NG]"
	ng=1
fi
if [ ${ng} -eq 0 ]; then
	echo "*** C${issue}T${tid}: PASSED"
else
	echo "*** C${issue}T${tid}: FAILED"
fi
echo ""

tid=06
ng=0
echo "*** C${issue}T${tid} start *******************************"
echo "** multi within-mapping with MAP_HUGETLB (expect mmap SUCCESS)"
${MCEXEC} ./hugemap `expr ${MEMALL} \* 4` ${INSIZE} -1

if [ $? -eq 0 ]; then
	echo "** [OK]"
else
	echo "** [NG]"
	ng=1
fi
if [ ${ng} -eq 0 ]; then
	echo "*** C${issue}T${tid}: PASSED"
else
	echo "*** C${issue}T${tid}: FAILED"
fi
