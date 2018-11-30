#!/bin/sh

# Tests with the number >= 0085 are invalid

make -C mcexec_test_proc

for i in {1..84}
do
	test_case="./testcases/"`printf "%04d" $i`"_mbind.txt"
	test_number=`basename ${test_case} _mbind.txt`
	case_name=`basename ${test_case} .txt`

	# Skip MPOL_INTERLEAVE tests because it's not supported
	if [ "`awk '/USR_PROC/ {print $2}' $test_case`" == "0x8003" ] ||
	   [ "`awk '/USR_PROC/ {print $5}' $test_case`" == "0x8003" ]; then
            echo "[INFO] ${case_name} is skipped because it's trying to test MPOL_INTERLEAVE"
	    continue
	fi

	logfile="./result/${case_name}.log"
	./mbind_test.sh ${test_case} &> ${logfile}

	if [ $? -eq 0 ]; then
	        ./chk_mbind_result.sh ${case_name}
        	if [ $? -eq 0 ]; then
               		echo "[ OK ] ${case_name} is done."
        	else
                	echo "[ NG ] failed to test ${case_name}. Please check ${logfile}"
        	fi
	else
		echo "[ NG ] failed to test ${case_name}. Please check ${logfile}"
	fi
done
