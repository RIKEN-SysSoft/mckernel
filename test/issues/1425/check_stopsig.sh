#!/bin/sh

rc=0
slptime=3

mcexec=$1
signame=$2

echo "** Exec sleep ${slptime}"
mcexec  sleep ${slptime} &
tgtpid=$!

echo "** TargetPID: ${tgtpid}"
stat_1=`ps -o stat,pid -p ${tgtpid} | grep ${tgtpid} | cut -f1 -d ' '`

if [ `echo ${stat_1} | grep -e "^S" | wc -l` -eq 1 ]; then
	echo "[OK] ${tgtpid} is running : ${stat_1}"
else
	echo "[NG] ${tgtpid} is NOT running : ${stat_1}"
	rc=1
fi

echo "** SEND SIG${signame} to ${tgtpid}"
kill -${signame} ${tgtpid}
sleep 1

stat_2=`ps -o stat,pid -p ${tgtpid} | grep ${tgtpid} | cut -f1 -d ' '`

if [ `echo ${stat_2} | grep -e "^T" | wc -l` -eq 1 ]; then
	echo "[OK] ${tgtpid} is stopped : ${stat_2}"
else
	echo "[NG] ${tgtpid} is NOT stopped : ${stat_2}"
	rc=1
fi

echo "** Sleep ${slptime} sec"
sleep ${slptime}

stat_3=`ps -o stat,pid -p ${tgtpid} | grep ${tgtpid} | cut -f1 -d ' '`

if [ `echo ${stat_2} | grep -e "^T" | wc -l` -eq 1 ]; then
	echo "[OK] ${tgtpid} is still stopped : ${stat_3}"
else
	echo "[NG] ${tgtpid} is NOT stopped : ${stat_3}"
	rc=1
fi

echo "** SEND SIGCONT to ${tgtpid}"
kill -CONT ${tgtpid}

echo "** Wait pid: ${tgtpid}"
wait ${tgtpid}

echo "[OK] pid: ${tgtpid} is Done."
exit ${rc}
