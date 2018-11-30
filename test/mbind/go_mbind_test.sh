#!/bin/sh
START_NG_TEST_NO=0085

make -C mcexec_test_proc

for test_case in `ls -1 ./testcases/*.txt`
do
	case_name=`basename ${test_case} .txt`

	logfile="./result/${case_name}.log"
	./mbind_test.sh ${test_case} &> ${logfile}

	if [ $? -eq 0 ]; then
	        ./chk_mbind_result.sh ${case_name}
        	if [ $? -eq 0 ]; then
               		echo "[OK] ${case_name} is done."
        	else
                	echo "[NG] failed to test ${case_name}. Please check ${logfile}"
        	fi
	else
		test_number=`basename ${test_case} _mbind.txt`
		if [ $test_number -ge $START_NG_TEST_NO ]; then
			echo "[OK] ${case_name} is done(NG test case)."
		else
			echo "[NG] failed to test ${case_name}. Please check ${logfile}"
		fi
	fi
done
