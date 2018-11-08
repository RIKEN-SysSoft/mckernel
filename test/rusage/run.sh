#!/usr/bin/bash

. ${HOME}/.mck_test_config

testname=$1
bootopt="-m 256M"
mcexecopt=""
testopt=""
kill="n"
dryrun="n"
sleepopt="0.4"

echo Executing ${testname}

case ${testname} in
    011 | 012)
	printf "*** Enable debug messages in rusage.h, memory.c, fileobj.c, shmobj.c, process.c by defining DEBUG macro, e.g. #define RUSAGE_DEBUG and then recompile IHK/McKernel.\n"
	printf "*** Install xpmem by git-clone https://github.com/hjelmn/xpmem.\n"
	;;
    100 | 101 | 102 | 103)
	printf "*** Refer to rusage100.patch to add syscall #900 by editing syscall_list.h and syscall.c and recompile IHK/McKernel.\n"
	;;
    200)
	printf "*** Apply rusage200.patch to enable syscall #900"
	printf "which reports rusage values.\n"
	;;
    *)
	printf "*** Enable debug messages in rusage.h, memory.c, fileobj.c, shmobj.c, process.c by defining DEBUG macro, e.g. #define RUSAGE_DEBUG and then recompile IHK/McKernel.\n"
	;;
esac

read -p "*** Hit return when ready!" key

case ${testname} in
    005)
	ssh wallaby -c '(cd ${HOME}/project/src/rusage/verbs; make rdma_wr)'
	bn_mck=verbs/rdma_wr
	;;
    019)
	#ssh wallaby -c '(cd ${HOME}/project/src/rusage/npb/NPB3.3.1-MZ/NPB3.3-MZ-MPI; make bt-mz CLASS=S NPROCS=2)'
	bn_mck=npb/NPB3.3.1-MZ/NPB3.3-MZ-MPI/bin/bt-mz.S.2
	perl -e 'print "wallaby14\nwallaby15\n"' > ./hostfile
	;;
    021)
	if ! grep /var/log/local6 /etc/rsyslog.conf &>/dev/null; then
	    echo "Insert a line of local6.* /var/log/local6 into /etc/rsyslog.conf"
	    exit 255
	fi
	ssh wallaby bash -c '(cd ${HOME}/project/src/rusage/npb/NPB3.3.1-MZ/NPB3.3-MZ-MPI; make bt-mz CLASS=S NPROCS=4)'
	bn_mck=npb/NPB3.3.1-MZ/NPB3.3-MZ-MPI/bin/bt-mz.S.4
	perl -e 'print "polaris:2\nkochab:2\n"' > ./hostfile
	;;
    200)
	bn_mck=${testname}_mck
	bn_lin=${testname}_lin
	make clean > /dev/null 2> /dev/null
	make $bn_mck $bn_lin
	;;
    *)
	bn_mck=${testname}_mck
	make clean > /dev/null 2> /dev/null
	make $bn_mck
esac

pid=`pidof mcexec`
if [ "${pid}" != "" ]; then
    kill -9 ${pid} > /dev/null 2> /dev/null 
fi

case ${testname} in
    000)
	testopt="0"
	;;
    010)
	testopt="1"
	;;
    020)
	bootopt="-m 256M@0,1G@0"
	testopt="2"
	kill="y"
	;;
    030)
	testopt="3"
	;;
    001)
	cp $bn_mck ./file
	kill="n"
	;;
    002)
	mcexecopt="--mpol-shm-premap"
	;;
    003)
	;;
    004)
	cp $bn_mck ./file
	;;
    005)
	echo ssh wallaby15.aics-sys.riken.jp ${HOME}/project/src/verbs/rdma_wr -p 10000&
	read -p "Run rdma_wr on wallaby15 and enter the port number." port
	testopt="-s wallaby15.aics-sys.riken.jp -p ${port}"
	;;
    006)
	mcexecopt="--mpol-shm-premap"
	;;
    007)
	;;
    008)
	cp $bn_mck ./file
	;;
    009)
	;;
    011)
	sudo insmod /home/takagi/usr/lib/module/xpmem.ko
	sudo chmod og+rw /dev/xpmem
	dryrun="n"
	kill="n"
	sleepopt="5"
	;;
    012)
	sudo insmod /home/takagi/usr/lib/module/xpmem.ko
	sudo chmod og+rw /dev/xpmem
	dryrun="n"
	kill="n"
	sleepopt="5"
	;;
    013 | 014 | 015 | 017)
	cp $bn_mck ./file
	;;
    016)
	;;
    018)
	;;
    019 | 021)
	bootopt="-k 1 -m 256M"
	;;
    100)
	;;
    101)
	;;
    102)
	cp $bn_lin ./file
	;;
    103)
	bootopt="-m 256M@1"
	;;
    200)
	bootopt="-c 1,2,3 -m 256M"
	;;
    *)
	echo Unknown test case
	exit 255
esac

if [ ${dryrun} == "y" ]; then
exit
fi

case ${testname} in
    019 | 021)
	sudo rm /var/log/local6
	sudo touch /var/log/local6
	sudo chmod 600 /var/log/local6
	sudo systemctl restart rsyslog
	;;
    *)
	;;
esac

case ${testname} in
    019 | 021)
	echo sudo ssh wallaby15 ${MCK_DIR}/sbin/mcstop+release.sh &&
	echo sudo ssh wallaby15 ${MCK_DIR}/sbin/mcreboot.sh
	read -p "Boot mckernel on wallaby15." ans
	;;
    *)
	;;
esac
sudo ${MCK_DIR}/sbin/mcstop+release.sh &&
sudo ${MCK_DIR}/sbin/mcreboot.sh ${bootopt}

if [ ${kill} == "y" ]; then
    ${MCK_DIR}/bin/mcexec ${mcexecopt} ./${bn} ${testopt} &
    sleep ${sleepopt}
    sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg > ./${testname}.log
    pid=`pidof mcexec`
    if [ "${pid}" != "" ]; then
	kill -9 ${pid} > /dev/null 2> /dev/null
    fi
else
    case ${testname} in
	005)
	    ${MCK_DIR}/bin/mcexec ${mcexecopt} ./${bn_mck} ${testopt}
	    #read -p "Run rdma_wr." ans
	    sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg > ./${testname}.log
	    ;;
	019 | 021)
	    echo OMP_NUM_THREADS=2 mpiexec -machinefile ./hostfile ${MCK_DIR}/bin/mcexec ${mcexecopt} ./${bn_mck} ${testopt}
	    read -p "Run ${bn_mck} and hit return." ans
	    sleep 1.5
	    sudo cat /var/log/local6 > ./${testname}.log
	    ;;
	100 | 101 | 102 | 103)
	    ${MCK_DIR}/bin/mcexec ${mcexecopt} ./${bn_mck} ${testopt} > ./${testname}.log
	    echo "================================================" >> ./${testname}.log
	    sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg >> ./${testname}.log
	    ;;
	200)
	    ${MCK_DIR}/bin/mcexec ${mcexecopt} ./${bn_mck}
	    ${MCK_DIR}/bin/mcexec ${mcexecopt} ./${bn_lin}
	    sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg > ./${testname}.log
	    grep user ./${testname}.log
	    ;;
	*)
	    ${MCK_DIR}/bin/mcexec ${mcexecopt} ./${bn_mck} ${testopt}
	    sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg > ./${testname}.log
    esac
fi


case ${testname} in
    011 | 012)
	sudo rmmod xpmem
	;;
    *)
	;;
esac

case ${testname} in
    100 | 101 | 102 | 103)
	printf "*** Check the ihk_os_getrusage() result (the first part of ${testname}.log) matches with the syscall #900 result (the second part) \n"
	;;
    200)
	printf "*** It behaves as expected when there's no [NG] and "
	printf "\"All tests finished\" is shown\n"
	;;
    *)
	printf "*** cat ${testname}.log (kmsg) > ./match.pl to confirm there's no stray add/sub.\n"
	printf "*** Look ${testname}.log (kmsg) to confirm memory_stat_*[*] returned to zero when the last thread exits.\n"
	;;
esac

sudo ${MCK_DIR}/sbin/mcstop+release.sh
