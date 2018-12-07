#!/bin/sh

# driver.sh [<test_set>]

test_set=$1

if [ "`git diff | grep -c 'large page allocation'`" == "0" ]; then
    echo "Perform \"patch -p0 < large_page.patch\""
    exit 1
fi

if [ "$test_set" == "" ]; then
    source ./test_set.conf
fi

if [ ! -d ./log ]; then
    mkdir log
fi

for i in $test_set
do
	test_id=$(printf "%03d" $i)

        echo "[INFO] ${test_id} started"

	../run.sh ${test_id} &> ./log/${test_id}.log

	if [ $? -ne 0 ]; then
		echo "[ NG ] ${test_id} run failed"
		continue
	fi

	../check.sh ${test_id}

        if [ $? -ne 0 ]; then
		echo "[ NG ] ${test_id} result check failed"
		continue
	fi

        echo "[ OK ] ${test_id} passed"
done
