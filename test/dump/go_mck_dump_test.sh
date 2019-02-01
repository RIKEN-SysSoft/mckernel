#!/bin/sh

for test_case in `ls -1 ./mck_testcases/*.txt`
do
	case_name=`basename ${test_case} .txt`

	mkdir -p "./result/mck_dump"

	logfile="./result/mck_dump/${case_name}.log"
	./mck_dump_test.sh ${test_case} &> ${logfile}

	if [ $? -eq 0 ]; then
		echo "[OK] ${case_name} is done."
	else
		echo "[NG] failed to test ${case_name}. Please check ${logfile}"
	fi

	# save dump_file
	#sudo mv mcdump_* ./result/${case_name}/ &> /dev/null
	#sudo mv dumps/dumpfile_* ./result/${case_name}/ &> /dev/null

	# remove dump_file
	sudo rm ./mcdump_* &> /dev/null
	sudo rm ./dumps/dumpfile_* &> /dev/null
done
