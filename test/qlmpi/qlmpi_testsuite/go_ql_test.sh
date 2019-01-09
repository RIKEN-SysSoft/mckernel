#!/bin/sh

for test_param in `ls -1 ./test_cases/CT*.txt`
do
	source ${test_param}
	./ql_normal.sh ${test_param} 2>&1 | tee ./result/${TEST_PREFIX}.log
done

./ql_irreg.sh ./test_cases/ECT91.txt

