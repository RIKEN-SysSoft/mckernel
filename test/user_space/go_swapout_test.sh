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

echo "pager_copy_from.patch for copy_from_user\(arealist_update,arealist_morereq,arealist_preparewrite,go_pageout\) test."
#patch copy_from_user
if [ ${auto_flg} -eq 1 ]; then
	cd ${TEST_DIR}
	sh ./patch_and_build.sh pager_copy_from.patch >/dev/null 
fi

#copy_from_user_test start
echo swapout 
cd ${TEST_DIR}/swapout
./swapout_copy_from.sh 2>&1 | tee ./swapout_copy_from.log
cd ${TEST_DIR}

echo "pager_copy_to_01.patch for copy_to_user\(arealist_update,arealist_add,do_pageout\) test."
#copy_to_user_test start
if [ ${auto_flg} -eq 1 ]; then
	cd ${TEST_DIR}
	sh ./patch_and_build.sh pager_copy_to_01.patch >/dev/null 
fi

echo swapout copy_to_user 1 test start
cd ${TEST_DIR}/swapout
./swapout_copy_to_01.sh 2>&1 | tee ./swapout_copy_to_01.log
cd ${TEST_DIR}

echo "pager_copy_to_02.patch for copy_to_user\(arealist_preparewrite,pager_open,pager_unlink,arealist_get,arealist_alloc\) test."
if [ ${auto_flg} -eq 1 ]; then
	cd ${TEST_DIR}
	sh ./patch_and_build.sh pager_copy_to_02.patch >/dev/null 
fi
echo swapout copy_to_user 2 test start
cd ${TEST_DIR}/swapout
./swapout_copy_to_02.sh 2>&1 | tee ./swapout_copy_to_02.log 
cd ${TEST_DIR}

echo "git reset --hard HEAD for swaptest execution test."
if [ ${auto_flg} -eq 1 ]; then
	cd ${TEST_DIR}
	sh ./patch_and_build.sh >/dev/null 
fi

echo swapout swaptest execution test start
cd ${TEST_DIR}/swapout
./swapout_normal.sh 2>&1 | tee ./swapout_normal.log
cd ${TEST_DIR}

echo "qlmpilib.patch for qlmpi test."
if [ ${auto_flg} -eq 1 ]; then
	cd ${TEST_DIR}
	sh ./patch_and_build.sh qlmpilib.patch >/dev/null 
fi

echo swapout qlmpi test start
cd ${TEST_DIR}/swapout
./ql_normal.sh ./test_cases/CT01.txt 2>&1 | tee ./ql_normal.log

cat ./swapout_copy_from.log ./swapout_copy_to_01.log ./swapout_copy_to_02.log ./swapout_normal.log ./ql_normal.log > ./swapout_test.log

rm ./swapout_copy_from.log ./swapout_copy_to_01.log ./swapout_copy_to_02.log ./swapout_normal.log ./ql_normal.log

cd ${TEST_DIR}

#最後にgitをresetしてビルドしなおす
if [ ${auto_flg} -eq 1 ]; then
	cd ${TEST_DIR}
	sh ./patch_and_build.sh >/dev/null 
fi
