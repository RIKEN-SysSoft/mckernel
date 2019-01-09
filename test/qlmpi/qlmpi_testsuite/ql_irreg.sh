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

function ng_out_cont {
	echo "[NG] ${TEST_PREFIX}`printf %03d ${TEST_NUM}` $1"
	(( TEST_NUM++ ))
	TEST_CODE=`printf %03d ${TEST_NUM}`
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

BK_PATH=${PATH}

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

### machinefile is not specified
env QL_TEST=${envs_1st_A} ${START} -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "machinefile is not specified, but ql_mpiexec_start returns 0"
else
	ok_out "machinefile is not specified, so ql_mpiexec_start returns not 0. returns ${rc}"
fi

### MPI program is not specified
env QL_TEST=${envs_1st_A} ${START} -n ${PROC_NUM} > ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "MPI program is not specified, but ql_mpiexec_start returns 0"
else
	ok_out "MPI program is not specified, so ql_mpiexec_start returns not 0. returns ${rc}"
fi

### specified machinefile does not exist
env QL_TEST=${envs_1st_A} ${START} -machinefile dose_not_exist -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "specified machinefile does not exist, but ql_mpiexec_start returns 0"
else
	ok_out "specified machinefile does not exist, so ql_mpiexec_start returns not 0. returns ${rc}"
fi

### specified MPI program does not exist
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} dose_not_exist ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "specified MPI program does not exist, but ql_mpiexec_start returns 0"
else
	ok_out "specified MPI program does not exist, so ql_mpiexec_start returns not 0. returns ${rc}"
fi

### mpiexec is not found
PATH="/usr/bin"
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "mpiexec is not found, but ql_mpiexec_start returns 0"
else
	ok_out "mpiexec is not found, so ql_mpiexec_start returns not 0. returns ${rc}"
fi
PATH=${BK_PATH}

### mpiexec abort
PATH="./util:/usr/bin"
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "mpiexec abort, but ql_mpiexec_start returns 0"
else
	ok_out "mpiexec abort, so ql_mpiexec_start returns not 0. returns ${rc}"
fi
PATH=${BK_PATH}

### machinefile is not specified
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log

${FINALIZE} -n ${PROC_NUM} ${USR_PRG_A} >> ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "machinefile is not specified, but ql_mpiexec_finalize returns 0"
else
	ok_out "machinefile is not specified, so ql_mpiexec_finalize returns not 0. returns ${rc}"
fi

### MPI program is not specified
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log
${FINALIZE} -machinefile ${MFILE} -n ${PROC_NUM} >> ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "MPI program is not specified, but ql_mpiexec_finalize returns 0"
else
	ok_out "MPI program is not specified, so ql_mpiexec_finalize returns not 0. returns ${rc}"
fi

### specified machinefile is wrong
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log
${FINALIZE} -machinefile ./util/wrong_mfile -n ${PROC_NUM} ${USR_PRG_A} >> ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "specified machinefile is wrong, but ql_mpiexec_finalize returns 0"
else
	ok_out "specified machinefile is wrong, so ql_mpiexec_finalize returns not 0. returns ${rc}"
fi

### specified MPI program name is wrong
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} ${args_1st_A} > ${RESULT_DIR}/${TEST_CODE}.log
${FINALIZE} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_B} >> ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "specified MPI program name is wrong, but ql_mpiexec_finalize returns 0"
else
	ok_out "specified MPI program name is wrong, so ql_mpiexec_finalize returns not 0. returns ${rc}"
fi

${FINALIZE} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_A} > /dev/null

### one of MPI process aborts
abort_rank=`expr ${PROC_NUM} - 1`
env QL_TEST=${envs_1st_A} ${START} -machinefile ${MFILE} -n ${PROC_NUM} ${USR_PRG_IRREG} 0 > ${RESULT_DIR}/${TEST_CODE}.log
rc=$?
if [ ${rc} -eq 0 ]; then
	ng_out_cont "one of MPI processes aborts, but ql_mpiexec_start returns  0"
else
	ok_out "one of MPI processes aborts, so ql_mpiexec_start returns not 0. returns ${rc}"
fi

