#!/usr/bin/bash

USELTP=0
USEOSTEST=0

XPMEM_DIR=$HOME/usr
XPMEM_BUILD_DIR=$HOME/project/src/xpmem

arch=`uname -p`
if [ -f "./${arch}_config" ]; then
	. ./${arch}_config
else
	echo "$1 is unexpected arch"
	exit 1
fi

. ../../common.sh

if false; then
sudo insmod ${XPMEM_DIR}/lib/modules/`uname -r`/xpmem.ko
sudo chmod og+rw /dev/xpmem

issue=1259
tid=01
ng=0
echo "*** C${issue}T${tid} start *******************************"
echo "** xpmem_attach to Huge mapped memory range"
echo "** end of range is aligned with Large page size"
for pgshift in ${PGSHIFT_LIST[@]}
do
	${IHKOSCTL} 0 clear_kmsg
	log_file="./C${issue}T${tid}_${pgshift}.log"
	echo pageshift: ${pgshift}
	${MCEXEC} ./huge_page_xpmem ${pgshift} 2 0 > ${log_file}
	${IHKOSCTL} 0 kmsg >> ${log_file}

	EXPECT_PGSIZE=`grep EXPECT_PAGE_SIZE ${log_file} | awk '{ print $2; }'`

	SEG_ADDR=`grep parent: ${log_file} | awk '{ print $3; }'`
	SEG_PGSIZE=`cat ${log_file} | awk '/OK/,/DONE/' | \
grep -o "large_page_allocation.*${SEG_ADDR}.*" | awk '{ print $5; }'`

	XPMEM_ADDR=`grep xpmem_attachment_addr ${log_file} | awk '{ print $3; }'`
	XPMEM_PGSIZE=`grep -o "xpmem_page_attach.*${XPMEM_ADDR}.*" ${log_file} | awk '{ print $5; }'`

	if [ "${SEG_PGSIZE}" = "${EXPECT_PGSIZE}" ]; then
		echo "** [ OK ] seg_addr ($SEG_ADDR) is allocated until xpmem_attach"
	else
		echo "** [ NG ] seg_addr ($SEG_ADDR) is NOT allocated until xpmem_attach"
		let ng++
	fi
	if [ "${XPMEM_PGSIZE}" = "${EXPECT_PGSIZE}" ]; then
		echo "** [ OK ] xpmem_addr ($XPMEM_ADDR) is allocated using large pages"
	else
		echo "** [ NG ] xpmem_addr ($XPMEM_ADDR) is NOT allocated using large pages"
		let ng++
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
echo "** xpmem_attach to Huge mapped memory range"
echo "** end of range is NOT aligned with Large page size"
for pgshift in ${PGSHIFT_LIST[@]}
do
	${IHKOSCTL} 0 clear_kmsg
	log_file="./C${issue}T${tid}_${pgshift}.log"
	echo pageshift: ${pgshift}
	${MCEXEC} ./huge_page_xpmem ${pgshift} 2 ${SMALL_PGSIZE} > ${log_file}
	${IHKOSCTL} 0 kmsg >> ${log_file}

	EXPECT_PGSIZE=`grep EXPECT_PAGE_SIZE ${log_file} | awk '{ print $2; }'`

	SEG_ADDR=`grep parent: ${log_file} | awk '{ print $3; }'`
	SEG_PGSIZE=`cat ${log_file} | awk '/OK/,/DONE/' | \
grep -o "large_page_allocation.*${SEG_ADDR}.*" | awk '{ print $5; }'`

	XPMEM_ADDR=`grep xpmem_attachment_addr ${log_file} | awk '{ print $3; }'`
	XPMEM_PGSIZE=`grep -o "xpmem_page_attach.*${XPMEM_ADDR}.*" ${log_file} | awk '{ print $5; }'`

	if [ "${SEG_PGSIZE}" = "${EXPECT_PGSIZE}" ]; then
		echo "** [ OK ] seg_addr ($SEG_ADDR) is allocated until xpmem_attach"
	else
		echo "** [ NG ] seg_addr ($SEG_ADDR) is NOT allocated until xpmem_attach"
		let ng++
	fi
	if [ "${XPMEM_PGSIZE}" = "${EXPECT_PGSIZE}" ]; then
		echo "** [ OK ] xpmem_addr ($XPMEM_ADDR) is allocated using large pages"
	else
		echo "** [ NG ] xpmem_addr ($XPMEM_ADDR) is NOT allocated using large pages"
		let ng++
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
echo "*** C${issue}T${tid} start *******************************"
echo "** xpmem_attach to small mapped memory range"
${IHKOSCTL} 0 clear_kmsg
log_file="./C${issue}T${tid}.log"
echo pageshift: small page
${MCEXEC} ./huge_page_xpmem -1 2 0 > ${log_file}
${IHKOSCTL} 0 kmsg >> ${log_file}

EXPECT_PGSIZE=`grep EXPECT_PAGE_SIZE ${log_file} | awk '{ print $2; }'`

XPMEM_ADDR=`grep xpmem_attachment_addr ${log_file} | awk '{ print $3; }'`
XPMEM_PGSIZE=`grep -o "xpmem_page_attach.*${XPMEM_ADDR}.*" ${log_file} | awk '{ print $5; }'`

if [ "${XPMEM_PGSIZE}" = "${EXPECT_PGSIZE}" ]; then
	echo "** [ OK ] xpmem_addr ($XPMEM_ADDR) is allocated using small pages"
else
	echo "** [ NG ] xpmem_addr ($XPMEM_ADDR) is NOT allocated using small pages"
	ng=1
fi
if [ ${ng} -eq 0 ]; then
	echo "*** C${issue}T${tid}: PASSED"
else
	echo "*** C${issue}T${tid}: FAILED"
fi
echo ""

tid=04
ng=0
echo "*** C${issue}T${tid} start *******************************"
echo "** xpmem_attach to multi pagesize range"
pgshift=${PGSHIFT_LIST[0]}
${IHKOSCTL} 0 clear_kmsg
log_file="./C${issue}T${tid}_${pgshift}.log"
echo pageshift: ${pgshift}
${MCEXEC} ./multi_vmr_xpmem ${pgshift} 1 > ${log_file}
${IHKOSCTL} 0 kmsg >> ${log_file}

EXPECT_PGSIZE=`grep EXPECT_PAGE_SIZE ${log_file} | awk '{ print $2; }'`

XPMEM_ADDR=`grep xpmem_large ${log_file} | awk '{ print $3; }'`
XPMEM_PGSIZE=`grep -o "xpmem_page_attach.*${XPMEM_ADDR}.*" ${log_file} | awk '{ print $5; }'`

if [ "${XPMEM_PGSIZE}" = "${EXPECT_PGSIZE}" ]; then
	echo "** [ OK ] xpmem_addr ($XPMEM_ADDR) is allocated using large pages"
else
	echo "** [ NG ] xpmem_addr ($XPMEM_ADDR) is NOT allocated using large pages"
	let ng++
fi
if [ ${ng} -eq 0 ]; then
	echo "*** C${issue}T${tid}: PASSED"
else
	echo "*** C${issue}T${tid}: FAILED"
fi
echo ""
fi

tid=05
ng=0
echo "*** C${issue}T${tid} start *******************************"
echo "** xpmem testsuite"
cwd=`pwd`
cd ${XPMEM_BUILD_DIR}/test
. ${cwd}/mc_run.sh
cd ${cwd}
exit 0
# xpmem basic test
${MCEXEC} ./XTP_001
${MCEXEC} ./XTP_002
${MCEXEC} ./XTP_003
${MCEXEC} ./XTP_004
${MCEXEC} ./XTP_005
${MCEXEC} ./XTP_006
sleep 3
${MCEXEC} ./XTP_007
${MCEXEC} ./XTP_008
${MCEXEC} ./XTP_009
${MCEXEC} ./XTP_010
${MCEXEC} ./XTP_011

sudo rmmod xpmem.ko
