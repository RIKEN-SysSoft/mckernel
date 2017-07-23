#!/bin/sh

# Functions
function ok_out() {
	echo "[OK] ${TEST_PREFIX}`printf %03d ${TEST_NUM}` $1"
	(( TEST_NUM++ ))
	TEST_CODE=`printf %03d ${TEST_NUM}`
}

function ng_out() {
	echo "[NG] ${TEST_PREFIX}`printf %03d ${TEST_NUM}` $1"
	exit 1
}

if [ $# -lt 1 ]; then
	echo "too few arguments."
	echo "usage: `basename $0` <param_file>"
fi

TEST_PARAM_FILE=$1
TEST_NUM=1
TEST_CODE=001

ME=`whoami`

# read config
source ./config

# read test param
source ${TEST_PARAM_FILE}

# make machinefile
mkdir ./machinefiles &> /dev/null
MFILE=./machinefiles/mfile_${TEST_PREFIX}
echo ${MASTER}:${PROC_PER_NODE} > ${MFILE}
for slave in ${SLAVE}
do
	echo ${slave}:${PROC_PER_NODE} >> ${MFILE}
done

PROC_NUM=`expr ${PROC_PER_NODE} \* ${MPI_NODE_NUM}`

# read machinefile
declare -a node_arry
while read line
do
	node_arry+=(${line%:*})
done < ${MFILE}
MASTER=${node_arry[0]}

# make result directory
RESULT_DIR=./result/${TEST_PREFIX}
mkdir -p ${RESULT_DIR}

RANK_MAX=`expr ${PROC_NUM} - 1`

# Log files
start_1st_A_log=${RESULT_DIR}/exec_1st_A.log
start_1st_B_log=${RESULT_DIR}/exec_1st_B.log
start_1st_C_log=${RESULT_DIR}/exec_1st_C.log

start_2nd_A_log=${RESULT_DIR}/exec_2nd_A.log
start_2nd_B_log=${RESULT_DIR}/exec_2nd_B.log
start_2nd_C_log=${RESULT_DIR}/exec_2nd_C.log

finalize_A_log=${RESULT_DIR}/finalize_A.log
finalize_B_log=${RESULT_DIR}/finalize_B.log
finalize_C_log=${RESULT_DIR}/finalize_C.log

# Arguments
args_1st_A="1234 hoge 02hoge"
args_2nd_A="foo 99bar test"

# Env
envs_1st_A="1st_exec_A"
envs_2nd_A="This_is_2nd_exec_A"

### テスト開始時点でql_serverとテスト用MPIプログラムが各ノードで実行されていない
for node in ${node_arry[@]}
do
	cnt=`ssh $node "pgrep -u ${ME} -c 'ql_(server|talker)'"`
	if [ ${cnt} -gt 0 ]; then
		ng_out "ql_server is running on ${node}"
	fi

	cnt=`ssh $node "pgrep -u ${ME} -c 'mpiexec'"`
	if [ ${cnt} -gt 0 ]; then
		ng_out "other MPI program is running on ${node}"
	fi
done
ok_out "ql_server and  usr_prgs are not running on each node"

### usr_prg_A を実行するql_mpiexec_start の返り値が0 (成功)
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${start_1st_A_log}
rc=$?
if [ ${rc} -eq 0 ]; then
	ok_out "ql_mpiexec_start usr_prg_A (first exec) returns 0"
else
	ng_out "ql_mpiexec_start usr_prg_A (first exec) returns ${rc}"
fi

### 初回実行後、マスターノード上でql_serverが動作している
cnt=`ssh ${MASTER} "pgrep -u ${ME} -c 'ql_server'"`
if [ ${cnt} -ne 1 ]; then
	ng_out "ql_server is not running on master node"
else
	ok_out "ql_server is running on master node"
fi

### 各ノードのusr_prg_A の引数が実行時に指定したものと一致している
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_1st_A_log} | grep -e "argv="`
	tgt=${line#*argv=}
	if [ "X${tgt}" != "X${USR_PRG_A} ${args_1st_A}" ]; then
		ng_out "usr_prg_A's args is incorrect on rank:${rank}\n ${line}"
	fi
done
ok_out "usr_prg_A's args are correct on each node"

### 各ノードのusr_prg_A テスト用に指定した環境変数が実行時に指定したものと一致している
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_1st_A_log} | grep -e "QL_TEST="`
	tgt=${line#*QL_TEST=}
	if [ "X${tgt}" != "X${envs_1st_A}" ]; then
		ng_out "usr_prg_A's env (QL_TEST) is incorrect on each node:${rank}\n ${line}"
	fi
done
ok_out "usr_prg_A's env (QL_TEST) is correct on each node"

### 各ノードのusr_prg_A の計算処理が完了
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_1st_A_log} | grep -e "done="`
	tgt=${line#*done=}
	if [ "X${tgt}" != "Xyes" ]; then
		ng_out "usr_prg_A's calculation is not done on rank:${rank}"
	fi
done
ok_out "usr_prg_A's calculation is done on each node"

### ql_mpiexec_start の完了後、usr_prg_A が再開指示待ちになっている
for node in ${node_arry[@]}
do
	cnt=`ssh $node "pgrep -u ${ME} -fl 'usr_prg_A'" | grep " exe" | wc -l`
	if [ ${cnt} -eq 0 ]; then
		ng_out "usr_prg_A is not running on ${node}"
	else
		echo "  ${cnt} programs is waiting on ${node}"
	fi
done
ok_out "usr_prg_A is waiting for resume-req on each node"

### usr_prg_B を実行するql_mpiexec_start の返り値が0 (成功)
${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_B} 1 2 3 > ${start_1st_B_log}
rc=$?
if [ ${rc} -eq 0 ]; then
	ok_out "ql_mpiexec_start usr_prg_B (first exec) returns 0"
else
	ng_out "ql_mpiexec_start usr_prg_B (first exec) returns ${rc}"
fi

### 各ノードのusr_prg_B の計算処理が完了
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_1st_B_log} | grep -e "done="`
	tgt=${line#*done=}
	if [ "X${tgt}" != "Xyes" ]; then
		ng_out "usr_prg_B's calculation is not done on rank:${rank}"
	fi
done
ok_out "usr_prg_B's calculation is done on each node"

### ql_mpiexec_start の完了後、usr_prg_B が再開指示待ちになっている
for node in ${node_arry[@]}
do
	cnt=`ssh $node "pgrep -u ${ME} -fl 'usr_prg_B'" | grep " exe" | wc -l`
	if [ ${cnt} -eq 0 ]; then
		ng_out "usr_prg_B is not running on ${node}"
	else
		echo "  ${cnt} programs is waiting on ${node}"
	fi
done
ok_out "usr_prg_B is waiting for resume-req on each node"

### usr_prg_C を実行するql_mpiexec_start の返り値が0 (成功)
${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_C} a b c > ${start_1st_C_log}
rc=$?
if [ ${rc} -eq 0 ]; then
	ok_out "ql_mpiexec_start usr_prg_C (first exec) returns 0"
else
	ng_out "ql_mpiexec_start usr_prg_C (first exec) returns ${rc}"
fi

### 各ノードのusr_prg_C の計算処理が完了
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_1st_C_log} | grep -e "done="`
	tgt=${line#*done=}
	if [ "X${tgt}" != "Xyes" ]; then
		ng_out "usr_prg_C's calculation is not done on rank:${rank}"
	fi
done
ok_out "usr_prg_C's calculation is done on each node"

### ql_mpiexec_start の完了後、usr_prg_C が再開指示待ちになっている
for node in ${node_arry[@]}
do
	cnt=`ssh $node "pgrep -u ${ME} -fl 'usr_prg_C'" | grep " exe" | wc -l`
	if [ ${cnt} -eq 0 ]; then
		ng_out "usr_prg_C is not running on ${node}"
	else
		echo "  ${cnt} programs is waiting on ${node}"
	fi
done
ok_out "usr_prg_C is waiting for resume-req on each node"

### usr_prg_A を再実行するql_mpiexec_start の返り値が0 (成功)
env QL_TEST=${envs_2nd_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} ${args_2nd_A} > ${start_2nd_A_log}
rc=$?
if [ ${rc} -eq 0 ]; then
	ok_out "(again) ql_mpiexec_start usr_prg_A returns 0"
else
	ng_out "(again) ql_mpiexec_start usr_prg_A returns ${rc}"
fi

### 各ノードのusr_prg_A の引数が再実行時に指定したものと一致している
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_2nd_A_log} | grep -e "argv="`
	tgt=${line#*argv=}
	if [ "X${tgt}" != "X${USR_PRG_A} ${args_2nd_A}" ]; then
		ng_out "usr_prg_A's args is incorrect on rank:${rank}\n ${line}"
	fi
done
ok_out "(again) usr_prg_A's args are correct on each node"

### 各ノードのusr_prg_A テスト用に指定した環境変数が再実行時に指定したものと一致している
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_2nd_A_log} | grep -e "QL_TEST="`
	tgt=${line#*QL_TEST=}
	if [ "X${tgt}" != "X${envs_2nd_A}" ]; then
		ng_out "usr_prg_A's env (QL_TEST) is incorrect on each node:${rank}\n ${line}"
	fi
done
ok_out "(again) usr_prg_A's env (QL_TEST) is correct on each node"

### 各ノードのusr_prg_A の計算処理が完了
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_2nd_A_log} | grep -e "done="`
	tgt=${line#*done=}
	if [ "X${tgt}" != "Xyes" ]; then
		ng_out "usr_prg_A's calculation is not done on rank:${rank}"
	fi
done
ok_out "(again) usr_prg_A's calculation is done on each node"

### ql_mpiexec_start の完了後、usr_prg_A が再開指示待ちになっている
for node in ${node_arry[@]}
do
	cnt=`ssh $node "pgrep -u ${ME} -fl 'usr_prg_A'" | grep " exe" | wc -l`
	if [ ${cnt} -eq 0 ]; then
		ng_out "usr_prg_A is not running on ${node}"
	else
		echo "  ${cnt} programs is waiting on ${node}"
	fi
done
ok_out "(again) usr_prg_A is waiting for resume-req on each node"

### usr_prg_B を再実行するql_mpiexec_start の返り値が0 (成功)
${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_B} 10 20 30 40 > ${start_2nd_B_log}
rc=$?
if [ ${rc} -eq 0 ]; then
	ok_out "(again) ql_mpiexec_start usr_prg_B returns 0"
else
	ng_out "(again) ql_mpiexec_start usr_prg_B returns ${rc}"
fi

### 各ノードのusr_prg_B の計算処理が完了
for rank in `seq 0 ${RANK_MAX}`
do
	line=`grep -e "^${rank}:" ${start_2nd_B_log} | grep -e "done="`
	tgt=${line#*done=}
	if [ "X${tgt}" != "Xyes" ]; then
		ng_out "usr_prg_B's calculation is not done on rank:${rank}"
	fi
done
ok_out "(again) usr_prg_B's calculation is done on each node"

### ql_mpiexec_start の完了後、usr_prg_B が再開指示待ちになっている
for node in ${node_arry[@]}
do
	cnt=`ssh $node "pgrep -u ${ME} -fl 'usr_prg_B'" | grep " exe" | wc -l`
	if [ ${cnt} -eq 0 ]; then
		ng_out "usr_prg_B is not running on ${node}"
	else
		echo "  ${cnt} programs is waiting on ${node}"
	fi
done
ok_out "(again) usr_prg_B is waiting for resume-req on each node"

### usr_prg_A を終了するql_mpiexec_finalize の返り値が0 (成功)
${FINALIZE} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} > ${finalize_A_log}
rc=$?
if [ ${rc} -eq 0 ]; then
	ok_out "ql_mpiexec_finalize usr_prg_A return 0"
else
	ng_out "ql_mpiexec_finalize usr_prg_A return ${rc}"
fi

### usr_prg_B を終了するql_mpiexec_finalize の返り値が0 (成功)
${FINALIZE} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_B} > ${finalize_B_log}
rc=$?
if [ ${rc} -eq 0 ]; then
	ok_out "ql_mpiexec_finalize usr_prg_B return 0"
else
	ng_out "ql_mpiexec_finalize usr_prg_B return ${rc}"
fi

### usr_prg_Bの終了後、ql_serverがマスターノード上で動作している
cnt=`ssh ${MASTER} "pgrep -u ${ME} -c 'ql_server'"`
if [ ${cnt} -ne 1 ]; then
	ng_out "ql_server is not running on master node"
else
	ok_out "ql_server is still running on master node"
fi

### usr_prg_C を終了するql_mpiexec_finalize の返り値が0 (成功)
${FINALIZE} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_C} > ${finalize_C_log}
rc=$?
if [ ${rc} -eq 0 ]; then
	ok_out "ql_mpiexec_finalize usr_prg_C return 0"
else
	ng_out "ql_mpiexec_finalize usr_prg_C return ${rc}"
fi

### すべてのMPIプログラムが終了したので、ql_serverが終了した
cnt=`ssh ${MASTER} "pgrep -u ${ME} -c 'ql_server'"`
sleep 1
if [ ${cnt} -eq 0 ]; then
	ok_out "ql_server is not running on master node"
else
	ng_out "ql_server is still running on master node"
fi

