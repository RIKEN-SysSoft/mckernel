#!/bin/sh
source ${HOME}/.mck_test_config

TEST_DIR=`pwd`
MC_HOME=`pwd`/../..

cd $MC_HOME

if [ $# -eq 1 ]; then
	PATCH_NAME=$1
	git reset --hard HEAD
	patch -p1 < ${TEST_DIR}/patch/${PATCH_NAME}
else 
	git reset --hard HEAD
fi
cd $MC_HOME
make clean
./configure --prefix=${MCK_DIR} --with-target=smp-x86 \
	--with-mpi=/usr/lib64/mpich-3.2 --enable-qlmpi $* > \
	/tmp/install.log
make >> /tmp/install.log
make install >> /tmp/install.log

# for wallaby
chmod 777 ${MCK_DIR}/etc

