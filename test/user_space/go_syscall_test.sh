#!/bin/sh

TEST_DIR=`pwd -P`

auto_flg=0
if [ $# = 1 ]; then
	if [ $1 = "auto" ]; then
		auto_flg=1
	else
		auto_flg=0
	fi
fi

#patch syscall.patch
if [ ${auto_flg} -eq 1 ]; then
	cd ${TEST_DIR}
	sh ./patch_and_build.sh syscall.patch >/dev/null
fi

echo perf_event_open test start
cd ${TEST_DIR}/perf_event_open
./perf_event_open_test.sh 2>&1 | tee ./perf_event_open_test.log
cd ${TEST_DIR}

echo futex test start
cd ${TEST_DIR}/futex
./futex_test.sh 2>&1 | tee ./futex_test.log
cd ${TEST_DIR}

echo process_vm_readv test start
cd ${TEST_DIR}/process_vm
./process_vm_readv_test.sh 2>&1 | tee ./process_vm_readv_test.log
echo process_vm_writev test start
./process_vm_writev_test.sh 2>&1 | tee ./process_vm_writev_test.log
cd ${TEST_DIR}

echo move_pages test start
cd ${TEST_DIR}/move_pages
./move_pages_test.sh 2>&1 | tee ./move_pages_test.log
cd ${TEST_DIR}


