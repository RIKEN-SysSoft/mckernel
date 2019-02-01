#!/bin/sh

source ./config

FORCE_STOP=${HOME}/tmp/force_stop_linux_dump
if [ -e ${FORCE_STOP} ]; then
	echo "force stopped Linux dump test "
	exit 1
fi

PANIC_LIST="./panic_list"
PROGRESS_FILE="${HOME}/progress_linux_dump_test.txt"

if [ ! -f ${PANIC_LIST} ]; then
	cp ${PANIC_LIST}.in ${PANIC_LIST}
fi

# check existing of done_panic
if [ -e ./done_panic ]; then
	# test of ldump2mcdump

	source ./done_panic

	# find latest vmcore file
	latest_vmcore_dir="/var/crash/`ls -1t /var/crash | head -1`"
	latest_vmcore="${latest_vmcore_dir}/vmcore"

	if [ ! -e ${latest_vmcore} ]; then
		echo "Error: latest vmcore is not found."
		exit 1
	fi

	for case_name in ${BELOW_CASES}
	do
		param_file=./linux_testcases/${case_name}.txt
		mkdir -p "./result/linux_dump"
		logfile="./result/linux_dump/${case_name}.log"

		./linux_dump_test.sh ${latest_vmcore} ${param_file} &> ${logfile}
		if [ $? -eq 0 ]; then
			echo "[OK] ${case_name} is done." >> ${PROGRESS_FILE}
		else
			echo "[NG] failed to test ${case_name}, Please check ${logfile}" >> ${PROGRESS_FILE}
		fi
	done

	rm ./done_panic
	# remove vmcore
	sudo rm -r ${latest_vmcore_dir}

	# remove dump_file
	sudo rm ./mcdump &> /dev/null
	sudo rm ./dumps/mcdump_* &> /dev/null
fi

# occur test panic
panic_param=`head -1 ./panic_list`
if [ "X${panic_param}" = "X" ]; then
	echo "All panic is done"
	exit 0
fi
sed -i -e "/`basename ${panic_param}`/d" ./panic_list
./linux_dump_panic.sh ${panic_param}

