#!/bin/sh

DEFAULT_POLICY_KIND="<default policy>"
#SHARED_POLICY_KIND="<default policy:Mapping of MAP_SHARED>"
NUMA_NODE_POLICY_KIND="<NUMA node policy>"

FILE_NAME=$1
CHK_LOG_FILE="./result/${FILE_NAME}.log"

source "./testcases/${FILE_NAME}.txt"
CHK_POLICY_KIND=${POLICY_KIND}

SET_MEM_POLICY=`grep "OK:set_mempolicy" $CHK_LOG_FILE | grep -o '(MPOL.*)'`
SET_POLICY_NUM=`grep -c1 "OK:mbind" $CHK_LOG_FILE`

for exec_num in `seq 0 $((SET_POLICY_NUM - 1))`
do

	if [ $exec_num -lt 10 ]; then
		NUMA_NODE_ADDR=`grep "OK:mbind" $CHK_LOG_FILE | grep -e "0$exec_num]" | grep -o '(0x.*000)'`
		NUMA_NODE_POLICY=`grep "OK:mbind" $CHK_LOG_FILE | grep -e "0$exec_num]" | grep -o '(MPOL.*)'`
	else
		NUMA_NODE_ADDR=`grep "OK:mbind" $CHK_LOG_FILE | grep -e "$exec_num]" | grep -o '(0x.*000)'`
		NUMA_NODE_POLICY=`grep "OK:mbind" $CHK_LOG_FILE | grep -e "$exec_num]" | grep -o '(MPOL.*)'`
	fi

	if [ "$CHK_POLICY_KIND" = "$DEFAULT_POLICY_KIND" ]; then
		SET_MEM_POLICY_NUM=`grep -v $NUMA_NODE_ADDR $CHK_LOG_FILE | grep -e "$CHK_POLICY_KIND" | grep -ce "$SET_MEM_POLICY"`
		if [ $SET_MEM_POLICY_NUM -gt 0 ]; then
			echo "OK:" $exec_num $CHK_POLICY_KIND" - not address" $NUMA_NODE_ADDR "test policy" $SET_MEM_POLICY "allocate num:" $SET_MEM_POLICY_NUM
			exit 0
		else
			echo "NG:" $exec_num $CHK_POLICY_KIND" - not address" $NUMA_NODE_ADDR "test policy" $SET_MEM_POLICY "allocate num:" $SET_MEM_POLICY_NUM
			exit 1
		fi
	fi

	ALLOCATE_POLICY=`grep "mckernel_allocate_aligned_pages_node" $CHK_LOG_FILE | grep -e $NUMA_NODE_ADDR | grep -e "$CHK_POLICY_KIND" | grep -o '(MPOL.*)'`

	if [ "$CHK_POLICY_KIND" = "$NUMA_NODE_POLICY_KIND" ]; then
		if [ $NUMA_NODE_POLICY != $ALLOCATE_POLICY ]; then
			echo "NG:" $exec_num $CHK_POLICY_KIND" - address" $NUMA_NODE_ADDR "test policy" $NUMA_NODE_POLICY "allocate policy" $ALLOCATE_POLICY
			exit 1
		else
			echo "OK:" $exec_num $CHK_POLICY_KIND" - address" $NUMA_NODE_ADDR "test policy" $NUMA_NODE_POLICY "allocate policy" $ALLOCATE_POLICY
		fi
	else
		if [ $SET_MEM_POLICY != $ALLOCATE_POLICY ]; then
			echo "NG:" $exec_num $CHK_POLICY_KIND" - address" $NUMA_NODE_ADDR "test policy" $SET_MEM_POLICY "allocate policy" $ALLOCATE_POLICY
			exit 1
		else
			echo "OK:" $exec_num $CHK_POLICY_KIND" - address" $NUMA_NODE_ADDR "test policy" $SET_MEM_POLICY "allocate policy" $ALLOCATE_POLICY
		fi
	fi
done

exit 0

