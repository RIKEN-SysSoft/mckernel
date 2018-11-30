#!/bin/sh

DEFAULT_POLICY_KIND="<default policy>"
SHARED_POLICY_KIND="<default policy:Mapping of MAP_SHARED>"
ADDR_POLICY_KIND="<addr policy>"

FILE_NAME=$1
CHK_LOG_FILE="./result/${FILE_NAME}.log"

source "./testcases/${FILE_NAME}.txt"

# Check map with default policy or address policy
CHK_POLICY_KIND=${POLICY_KIND}

SET_MEM_POLICY=`grep "OK:set_mempolicy" $CHK_LOG_FILE | grep -o '(MPOL.*)'`

# Number of mbind trials
SET_POLICY_NUM=`grep -c1 "OK:mbind" $CHK_LOG_FILE`

for exec_num in `seq 0 $((SET_POLICY_NUM - 1))`
do

	if [ $exec_num -lt 10 ]; then
		ADDR=`grep "OK:mbind" $CHK_LOG_FILE | grep -e "0$exec_num]" | grep -o '(0x.*000)'`
		ADDR_POLICY=`grep "OK:mbind" $CHK_LOG_FILE | grep -e "0$exec_num]" | grep -o '(MPOL.*)'`
	else
		ADDR=`grep "OK:mbind" $CHK_LOG_FILE | grep -e "$exec_num]" | grep -o '(0x.*000)'`
		ADDR_POLICY=`grep "OK:mbind" $CHK_LOG_FILE | grep -e "$exec_num]" | grep -o '(MPOL.*)'`
	fi

	# Not-mbound and mapped with default policy?
	if [ "$CHK_POLICY_KIND" = "$DEFAULT_POLICY_KIND" ] ||
	   [ "$CHK_POLICY_KIND" = "$SHARED_POLICY_KIND" ]; then
		SET_MEM_POLICY_NUM=`grep -v $ADDR $CHK_LOG_FILE | grep -e "$CHK_POLICY_KIND" | grep -ce "$SET_MEM_POLICY"`
		if [ $SET_MEM_POLICY_NUM -gt 0 ]; then
			printf "\tOK:"
		else
 			printf "\tNG:"
		fi
		echo " ($exec_num) $SET_MEM_POLICY_NUM allocations using $CHK_POLICY_KIND for addresses excluding $ADDR found."
		if [ $SET_MEM_POLICY_NUM -gt 0 ]; then
			exit 0
		else
			exit 1
		fi
	fi

	ALLOCATE_POLICY=`grep "mckernel_allocate_aligned_pages_node" $CHK_LOG_FILE | grep -e $ADDR | grep -e "$CHK_POLICY_KIND" | grep -o '(MPOL.*)'`

	if [ "$CHK_POLICY_KIND" = "$ADDR_POLICY_KIND" ]; then
		# mbound and mapped with address policy?
		if [ $ADDR_POLICY != "$ALLOCATE_POLICY" ]; then
			printf "\tNG:"
		else
			printf "\tOK:"
		fi

		printf " ($exec_num) Kernel decision "
		printf "($CHK_POLICY_KIND: $ALLOCATE_POLICY)"

		if [ $ADDR_POLICY != "$ALLOCATE_POLICY" ]; then
			printf " doesn't match to"
		else
			printf " maches to"
		fi
		echo " user direction $ADDR_POLICY via mbind for $ADDR"
		if [ $ADDR_POLICY != "$ALLOCATE_POLICY" ]; then
			exit 1
		fi
	else
		# mbound and mapped with default policy?
		if [ $SET_MEM_POLICY != "$ALLOCATE_POLICY" ]; then
			printf "\tNG:"
		else
			printf "\tOK:"
		fi

		printf " ($exec_num) Kernel decision "
		printf "($CHK_POLICY_KIND: $ALLOCATE_POLICY)"

		if [ $SET_MEM_POLICY != "$ALLOCATE_POLICY" ]; then
			printf " doesn't match to"
		else
			printf " maches to"
		fi
		echo " user direction $SET_MEM_POLICY via set_mempolicy for address excluding $ADDR"
		if [ $SET_MEM_POLICY != "$ALLOCATE_POLICY" ]; then
			exit 1
		fi
	fi
done

exit 0

