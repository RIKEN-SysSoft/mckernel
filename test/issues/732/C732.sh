#!/bin/sh

USELTP=0
USEOSTEST=0

. ../../common.sh

tid=001
echo "*** CT_${tid} start ***************************"
fail=0
tgt_file=maps

${MCEXEC} cat -v /proc/self/${tgt_file} | tee ./CT_${tid}.txt
tail -1 CT_${tid}.txt | grep -e "\^@$"

if [ $? != 0 ]; then
	echo "[OK] end of /proc/<PID>/${tgt_file} is not NULL character"
else
	echo "[NG] end of /proc/<PID>/${tgt_file} is unnecessary NULL character"
	fail=1
fi

if [ X${fail} != X0 ]; then
	echo "*** CT_${tid} FAILED"
else
	echo "*** CT_${tid} PASSED"
fi
echo ""

tid=002
echo "*** CT_${tid} start ***************************"
fail=0
tgt_file=stat

${MCEXEC} cat -v /proc/self/${tgt_file} | tee ./CT_${tid}.txt
tail -1 CT_${tid}.txt | grep -e "\^@$"

if [ $? != 0 ]; then
	echo "[OK] end of /proc/<PID>/${tgt_file} is not NULL character"
else
	echo "[NG] end of /proc/<PID>/${tgt_file} is unnecessary NULL character"
	fail=1
fi

if [ X${fail} != X0 ]; then
	echo "*** CT_${tid} FAILED"
else
	echo "*** CT_${tid} PASSED"
fi
echo ""

tid=003
echo "*** CT_${tid} start ***************************"
fail=0
tgt_file=status

${MCEXEC} cat -v /proc/self/${tgt_file} | tee ./CT_${tid}.txt
tail -1 CT_${tid}.txt | grep -e "\^@$"

if [ $? != 0 ]; then
	echo "[OK] end of /proc/<PID>/${tgt_file} is not NULL character"
else
	echo "[NG] end of /proc/<PID>/${tgt_file} is unnecessary NULL character"
	fail=1
fi

if [ X${fail} != X0 ]; then
	echo "*** CT_${tid} FAILED"
else
	echo "*** CT_${tid} PASSED"
fi
echo ""

tid=004
echo "*** CT_${tid} start ***************************"
fail=0
tgt_file=stack

${MCEXEC} cat -v /proc/self/${tgt_file} | tee ./CT_${tid}.txt
tail -1 CT_${tid}.txt | grep -e "\^@$"

if [ $? != 0 ]; then
	echo "[OK] end of /proc/<PID>/${tgt_file} is not NULL character"
else
	echo "[NG] end of /proc/<PID>/${tgt_file} is unnecessary NULL character"
	fail=1
fi

if [ X${fail} != X0 ]; then
	echo "*** CT_${tid} FAILED"
else
	echo "*** CT_${tid} PASSED"
fi
echo ""

tid=005
echo "*** CT_${tid} start ***************************"
fail=0
tgt_file=numa_maps

${MCEXEC} cat -v /proc/self/${tgt_file} | tee ./CT_${tid}.txt
tail -1 CT_${tid}.txt | grep -e "\^@$"

if [ $? != 0 ]; then
	echo "[OK] end of /proc/<PID>/${tgt_file} is not NULL character"
else
	echo "[NG] end of /proc/<PID>/${tgt_file} is unnecessary NULL character"
	fail=1
fi

if [ X${fail} != X0 ]; then
	echo "*** CT_${tid} FAILED"
else
	echo "*** CT_${tid} PASSED"
fi
echo ""
