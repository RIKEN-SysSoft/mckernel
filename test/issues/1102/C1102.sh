#!/bin/sh

USELTP=1
USEOSTEST=1

. ../../common.sh

tid=001
echo "*** CT_${tid} start *******************"
fail=0
REP=30
echo "** exec ltp-syscall_mkdir09  ${REP} times"
echo -n "" > ./CT_${tid}.txt
for i in `seq 1 ${REP}`
do
	${MCEXEC} ${LTPBIN}/mkdir09 | tee -a ./CT_${tid}.txt
done

grep -a -e "FAIL" ./CT_${tid}.txt

if [ $? != 0 ]; then
	echo "[OK] ltp-syscall_mkdir09  ${REP} times all passed"
else
	echo "[NG] ltp-syscall_mkdir09  failed"
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
echo "** exec ostest siginfo_00"
${MCEXEC} ${TESTMCK} -s siginfo -n 0| tee -a ./CT_${tid}.txt

tail -n 1 ./CT_${tid}.txt | grep -a -e "RESULT: ok" &> /dev/null

if [ $? = 0 ]; then
	echo "[OK] ostest siginfo_00  passed"
else
	echo "[NG] ostest siginfo_00  failed"
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
SIG_NAME=SIGHUP
SIG_NUM=1
echo "** exec ostest siginfo_01 and then send ${SIG_NAME} to mcexec"
${MCEXEC} ${TESTMCK} -s siginfo -n 1 &
sleep 1

echo "** back ground process(mcexec): $!"
echo "** send ${SIG_NAME} to mcexec once"
kill -${SIG_NUM} $!
sleep 1

echo "** check existing of $!"
ps -p $!

if [ $? = 0 ]; then
	echo "[OK] $! exists yet"
else
	echo "[NG] $! doesn't exist"
	fail=1
fi

echo "** send ${SIG_NAME} to mcexec again"
kill -${SIG_NUM} $!
sleep 1
echo "** check existing of $!"
ps -p $!

if [ $? != 0 ]; then
	echo "[OK] $! doesn't exist (be killed by signal)"
else
	echo "[NG] exist yet"
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
SIG_NAME=SIGINT
SIG_NUM=2
echo "** exec ostest siginfo_01 and then send ${SIG_NAME} to mcexec"
${MCEXEC} ${TESTMCK} -s siginfo -n 1 &
sleep 1

echo "** back ground process(mcexec): $!"
echo "** send ${SIG_NAME} to mcexec once"
kill -${SIG_NUM} $!
sleep 1

echo "** check existing of $!"
ps -p $!

if [ $? = 0 ]; then
	echo "[OK] $! exists yet"
else
	echo "[NG] $! doesn't exist"
	fail=1
fi

echo "** send ${SIG_NAME} to mcexec again"
kill -${SIG_NUM} $!
sleep 1
echo "** check existing of $!"
ps -p $!

if [ $? != 0 ]; then
	echo "[OK] $! doesn't exist (be killed by signal)"
else
	echo "[NG] exist yet"
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
SIG_NAME=SIGTERM
SIG_NUM=15
echo "** exec ostest siginfo_01 and then send ${SIG_NAME} to mcexec"
${MCEXEC} ${TESTMCK} -s siginfo -n 1 &
sleep 1

echo "** back ground process(mcexec): $!"
echo "** send ${SIG_NAME} to mcexec once"
kill -${SIG_NUM} $!
sleep 1

echo "** check existing of $!"
ps -p $!

if [ $? = 0 ]; then
	echo "[OK] $! exists yet"
else
	echo "[NG] $! doesn't exist"
	fail=1
fi

echo "** send ${SIG_NAME} to mcexec again"
kill -${SIG_NUM} $!
sleep 1
echo "** check existing of $!"
ps -p $!

if [ $? != 0 ]; then
	echo "[OK] $! doesn't exist (be killed by signal)"
else
	echo "[NG] exist yet"
	fail=1
fi

if [ X$fail = X0 ]; then
	echo "*** CT_${tid} PASSED"
else
	echo "*** CT_${tid} FAILED"
fi
echo ""

