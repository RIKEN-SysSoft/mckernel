#!/bin/sh

USELTP=1
USEOSTEST=0

if [ $# -lt 1 ]; then
	echo "usage: C1181.sh <arch>"
	exit 1
fi

. ../../common.sh

if [ -f "./$1_config" ]; then
	. ./$1_config
else
	echo "$1 is unexpected arch"
	exit 1
fi

tid=001
echo "*** CT$tid start *******************************"
echo "** case: THP_DISABLED"
./set_thp_and_exec 1 ${MCEXEC} ./check_thp 1 | tee ./CT${tid}.txt
echo "** case: THP_ENABLED"
./set_thp_and_exec 0 ${MCEXEC} ./check_thp 0 | tee -a ./CT${tid}.txt
ok=`grep "\[ OK \]" CT${tid}.txt | wc -l`
ng=`grep "\[ NG \]" CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok, ng:$ng)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi

LARGE_PAGE_STR="large page allocation"
echo ""
tid=002
echo "*** CT$tid start *******************************"
echo "** case: THP_DISABLED"
${IHKOSCTL} 0 clear_kmsg
./set_thp_and_exec 1 ${MCEXEC} ./mmap_large
${IHKOSCTL} 0 kmsg > ./CT${tid}_01.txt
if grep "${LARGE_PAGE_STR}" ./CT${tid}_01.txt &> /dev/null ; then
	echo "[ NG ] THP is Working" | tee ./CT${tid}.txt
else
	echo "[ OK ] THP is NOT Working" | tee ./CT${tid}.txt
fi

echo "** case: THP_ENABLED"
${IHKOSCTL} 0 clear_kmsg
./set_thp_and_exec 0 ${MCEXEC} ./mmap_large
${IHKOSCTL} 0 kmsg > ./CT${tid}_02.txt
if grep "${LARGE_PAGE_STR}" ./CT${tid}_02.txt &> /dev/null ; then
	pgsize_allocated=`grep "large page allocation" ./CT${tid}_02.txt | tail -1 | grep -oE 'size: \w*' | sed 's/size: //'`
	echo "pgsize_allocated: ${pgsize_allocated}"
	if [ "$pgsize_allocated" == "${MMAP_LARGE}" ]; then
		echo "[ OK ] THP is Working well" | tee -a ./CT${tid}.txt
	else
		echo "[ NG ] THP is Working, but pgsize is INVALID" | tee -a ./CT${tid}.txt
	fi
else
	echo "[ NG ] when THP is ENABLED, NOT Working" | tee -a ./CT${tid}.txt
fi

ok=`grep "\[ OK \]" CT${tid}.txt | wc -l`
ng=`grep "\[ NG \]" CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok, ng:$ng)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi

echo ""
tid=003
echo "*** CT$tid start *******************************"
echo "** case: THP_DISABLED"
${IHKOSCTL} 0 clear_kmsg
./set_thp_and_exec 1 ${MCEXEC} ./shm_large
${IHKOSCTL} 0 kmsg > ./CT${tid}_01.txt
if grep "${LARGE_PAGE_STR}" ./CT${tid}_01.txt &> /dev/null ; then
	pgsize_allocated=`grep "large page allocation" ./CT${tid}_01.txt | tail -1 | grep -oE 'size: \w*' | sed 's/size: //'`
	echo "pgsize_allocated: ${pgsize_allocated}"
	if [ "$pgsize_allocated" == "${SHM_LARGE}" ]; then
		echo "[ OK ] THP is NOT Working" | tee ./CT${tid}.txt
	else
		echo "[ NG ] pgsize is INVALID" | tee ./CT${tid}.txt
	fi
else
	echo "[ NG ] large page is NOT Working" | tee ./CT${tid}.txt
fi

echo "** case: THP_ENABLED"
${IHKOSCTL} 0 clear_kmsg
./set_thp_and_exec 0 ${MCEXEC} ./shm_large
${IHKOSCTL} 0 kmsg > ./CT${tid}_02.txt
if grep "${LARGE_PAGE_STR}" ./CT${tid}_02.txt &> /dev/null ; then
	pgsize_allocated=`grep "large page allocation" ./CT${tid}_02.txt | tail -1 | grep -oE 'size: \w*' | sed 's/size: //'`
	echo "pgsize_allocated: ${pgsize_allocated}"
	if [ "$pgsize_allocated" == "${SHM_HUGE}" ]; then
		echo "[ OK ] THP is Working well" | tee -a ./CT${tid}.txt
	else
		echo "[ NG ] THP is Working, but pgsize is INVALID" | tee -a ./CT${tid}.txt
	fi
else
	echo "[ NG ] large page is NOT Working" | tee -a ./CT${tid}.txt
fi

ok=`grep "\[ OK \]" CT${tid}.txt | wc -l`
ng=`grep "\[ NG \]" CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok, ng:$ng)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi

# init for hugetlbfs test
sudo mkdir -p /mnt/hugetlbfs-2M
sudo mount -t hugetlbfs -o mode=777,pagesize=2m none /mnt/hugetlbfs-2M

sudo mkdir -p /mnt/hugetlbfs-1G
sudo mount -t hugetlbfs -o mode=777,pagesize=1g none /mnt/hugetlbfs-1G
echo ""
tid=004
echo "*** CT$tid start *******************************"
echo "** case: THP_DISABLED"
${IHKOSCTL} 0 clear_kmsg
./set_thp_and_exec 1 ${MCEXEC} ./mmap_hugetlbfs
${IHKOSCTL} 0 kmsg > ./CT${tid}_01.txt
if grep "${LARGE_PAGE_STR}" ./CT${tid}_01.txt &> /dev/null ; then
	pgsize_allocated=`grep "large page allocation" ./CT${tid}_01.txt | head -1 | grep -oE 'size: \w*' | sed 's/size: //'`
	echo "pgsize_allocated: ${pgsize_allocated}"
	if [ "$pgsize_allocated" == "${SIZE_2M}" ]; then
		echo "[ OK ] hugetlbfs-2M is Working well" | tee ./CT${tid}.txt
	else
		echo "[ NG ] pgsize is INVALID" | tee ./CT${tid}.txt
	fi

	pgsize_allocated=`grep "large page allocation" ./CT${tid}_01.txt | tail -1 | grep -oE 'size: \w*' | sed 's/size: //'`
	echo "pgsize_allocated: ${pgsize_allocated}"
	if [ "$pgsize_allocated" == "${SIZE_1G}" ]; then
		echo "[ OK ] hugetlbfs-1G is Working well" | tee -a ./CT${tid}.txt
	else
		echo "[ NG ] pgsize is INVALID" | tee -a ./CT${tid}.txt
	fi
else
	echo "[ NG ] hugetlbfs-1G is NOT Working" | tee ./CT${tid}.txt
fi

echo "** case: THP_ENABLED"
${IHKOSCTL} 0 clear_kmsg
./set_thp_and_exec 0 ${MCEXEC} ./mmap_hugetlbfs
${IHKOSCTL} 0 kmsg > ./CT${tid}_02.txt
if grep "${LARGE_PAGE_STR}" ./CT${tid}_02.txt &> /dev/null ; then
	pgsize_allocated=`grep "large page allocation" ./CT${tid}_02.txt | head -1 | grep -oE 'size: \w*' | sed 's/size: //'`
	echo "pgsize_allocated: ${pgsize_allocated}"
	if [ "$pgsize_allocated" == "${SIZE_2M}" ]; then
		echo "[ OK ] hugetlbfs-2M is Working well" | tee -a ./CT${tid}.txt
	else
		echo "[ NG ] pgsize is INVALID" | tee -a ./CT${tid}.txt
	fi

	pgsize_allocated=`grep "large page allocation" ./CT${tid}_02.txt | tail -1 | grep -oE 'size: \w*' | sed 's/size: //'`
	echo "pgsize_allocated: ${pgsize_allocated}"
	if [ "$pgsize_allocated" == "${SIZE_1G}" ]; then
		echo "[ OK ] hugetlbfs-1G is Working well" | tee -a ./CT${tid}.txt
	else
		echo "[ NG ] pgsize is INVALID" | tee -a ./CT${tid}.txt
	fi
else
	echo "[ NG ] hugetlbfs-1G is NOT Working" | tee -a ./CT${tid}.txt
fi

ok=`grep "\[ OK \]" CT${tid}.txt | wc -l`
ng=`grep "\[ NG \]" CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok, ng:$ng)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
# fini for hugetlbfs test
sudo umount /mnt/hugetlbfs-2M
sudo umount /mnt/hugetlbfs-1G

echo ""
tid=005
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/prctl01 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok, ng:$ng)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi

echo ""
tid=006
echo "*** CT$tid start *******************************"
sudo ${MCEXEC} ${LTPBIN}/prctl02 2>&1 | tee ./CT${tid}.txt
ok=`grep TPASS CT${tid}.txt | wc -l`
ng=`grep TFAIL CT${tid}.txt | wc -l`
if [ $ng = 0 ]; then
	echo "*** CT$tid: PASSED (ok:$ok, ng:$ng)"
else
	echo "*** CT$tid: FAILED (ok:$ok, ng:$ng)"
fi
