#!/bin/sh

ASSIGNED_MEM=`echo '1024 * 1024 * 1024 * 20' | bc`
cat /proc/meminfo > ./cur_meminfo.txt

# Check MemTotal
MemTotalTxt=`cat ./cur_meminfo.txt | grep MemTotal | awk '{print $(NF-1)}'`
MemTotal=`echo "1024 * ${MemTotalTxt}" | bc`

lower_limit=`echo "${ASSIGNED_MEM} * 0.95" | bc`
lower_limit=${lower_limit%.*}
upper_limit=${ASSIGNED_MEM}
tgt=${MemTotal}

if [ ${tgt} -ge ${lower_limit} -a ${tgt} -lt ${upper_limit} ]; then
	echo "[OK] MemTotal: ${tgt}"
else
	echo "[NG] unexpected MemTotal: ${tgt}"
	exit 1
fi

# Check MemFree
MemFreeTxt=`cat ./cur_meminfo.txt | grep MemFree | awk '{print $(NF-1)}'`
MemFree=`echo "1024 * ${MemFreeTxt}" | bc`

lower_limit=`echo "${MemTotal} * 0.95" | bc`
lower_limit=${lower_limit%.*}
upper_limit=${MemTotal}
tgt=${MemFree}

if [ ${tgt} -ge ${lower_limit} -a ${tgt} -lt ${upper_limit} ]; then
	echo "[OK] MemFree: ${tgt}"
else
	echo "[NG] unexpected MemFree: ${tgt}"
	exit 1
fi

# Check SwapTotal
SwapTotalTxt=`cat ./cur_meminfo.txt | grep SwapTotal | awk '{print $(NF-1)}'`
SwapTotal=`echo "1024 * ${SwapTotalTxt}" | bc`

tgt=${SwapTotal}

if [ ${tgt} -eq 0 ]; then
	echo "[OK] SwapTotal: ${tgt}"
else
	echo "[NG] unexpected SwapTotal: ${tgt}"
	exit 1
fi

# Check SwapFree
SwapFreeTxt=`cat ./cur_meminfo.txt | grep SwapFree | awk '{print $(NF-1)}'`
SwapFree=`echo "1024 * ${SwapFreeTxt}" | bc`

tgt=${SwapFree}

if [ ${tgt} -eq 0 ]; then
	echo "[OK] SwapFree: ${tgt}"
else
	echo "[NG] unexpected SwapFree: ${tgt}"
	exit 1
fi

# Check CommitLimit
CommitLimitTxt=`cat ./cur_meminfo.txt | grep CommitLimit | awk '{print $(NF-1)}'`
CommitLimit=`echo "1024 * ${CommitLimitTxt}" | bc`

tgt=${CommitLimit}

if [ ${tgt} -eq ${MemFree} ]; then
	echo "[OK] CommitLimit: ${tgt}"
else
	echo "[NG] unexpected CommitLimit: ${tgt}"
	exit 1
fi

# Check Committed_AS
Committed_ASTxt=`cat ./cur_meminfo.txt | grep Committed_AS | awk '{print $(NF-1)}'`
Committed_AS=`echo "1024 * ${Committed_ASTxt}" | bc`

tgt=${Committed_AS}

if [ ${tgt} -eq $((${MemTotal} - ${MemFree})) ]; then
	echo "[OK] Committed_AS: ${tgt}"
else
	echo "[NG] unexpected Committed_AS: ${tgt}"
	exit 1
fi
