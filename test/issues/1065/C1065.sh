#!/bin/sh

USELTP=0
USEOSTEST=0

. ../../common.sh

tid=001
echo "*** CT_${tid} start *******************"
fail=0
map_path=`realpath ./dummy_file`
real_path=`realpath ${map_path}`

echo "file map: ${map_path}"

${MCEXEC} ./file_map ${map_path} | tee  ./CT_${tid}.txt
if [ X$? != X0 ]; then
	fail=1
fi

echo ""
echo "** grep ${real_path} from maps"
grep -a -e "${real_path}$" ./CT_${tid}.txt

if [ X$? = X0 ]; then
	echo "[OK] ${real_path} is found"
else
	echo "[NG] ${real_path} is not found"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** CT_${tid} PASSED"
else
	echo "*** CT_${tid} FAILED"
fi
echo ""

tid=002
echo "*** CT_${tid} start *******************"
fail=0
map_path="./dummy_file"
real_path=`realpath ${map_path}`

echo "file map: ${map_path}"

${MCEXEC} ./file_map ${map_path} | tee  ./CT_${tid}.txt
if [ X$? != X0 ]; then
	fail=1
fi

echo ""
echo "** grep ${real_path} from maps"
grep -a -e "${real_path}$" ./CT_${tid}.txt

if [ X$? = X0 ]; then
	echo "[OK] ${real_path} is found"
else
	echo "[NG] ${real_path} is not found"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** CT_${tid} PASSED"
else
	echo "*** CT_${tid} FAILED"
fi
echo ""

tid=003
echo "*** CT_${tid} start *******************"
fail=0
map_path=`realpath ./lnk_to_dummy`
real_path=`realpath ${map_path}`

echo "file map: ${map_path}"

${MCEXEC} ./file_map ${map_path} | tee  ./CT_${tid}.txt
if [ X$? != X0 ]; then
	fail=1
fi

echo ""
echo "** grep ${real_path} from maps"
grep -a -e "${real_path}$" ./CT_${tid}.txt

if [ X$? = X0 ]; then
	echo "[OK] ${real_path} is found"
else
	echo "[NG] ${real_path} is not found"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** CT_${tid} PASSED"
else
	echo "*** CT_${tid} FAILED"
fi
echo ""

tid=004
echo "*** CT_${tid} start *******************"
fail=0
map_path="./lnk_to_dummy"
real_path=`realpath ${map_path}`

echo "file map: ${map_path}"

${MCEXEC} ./file_map ${map_path} | tee  ./CT_${tid}.txt
if [ X$? != X0 ]; then
	fail=1
fi

echo ""
echo "** grep ${real_path} from maps"
grep -a -e "${real_path}$" ./CT_${tid}.txt

if [ X$? = X0 ]; then
	echo "[OK] ${real_path} is found"
else
	echo "[NG] ${real_path} is not found"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** CT_${tid} PASSED"
else
	echo "*** CT_${tid} FAILED"
fi
echo ""

tid=005
echo "*** CT_${tid} start *******************"
fail=0
map_path="./dummy_file"

echo "check [vdso], [stack]"

${MCEXEC} ./file_map ${map_path} | tee  ./CT_${tid}.txt
if [ X$? != X0 ]; then
	fail=1
fi

echo ""
for tgt in "\[vdso\]" "\[stack\]"
do
	echo "** grep ${tgt} from maps"
	grep -a -e "${tgt}$" ./CT_${tid}.txt

	if [ X$? = X0 ]; then
		echo "[OK] ${tgt} is found"
	else
		echo "[NG] ${tgt} is not found"
		fail=1
	fi
done

if [ X$fail = X0 ]; then
	echo "*** CT_${tid} PASSED"
else
	echo "*** CT_${tid} FAILED"
fi
echo ""
