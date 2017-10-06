#!/usr/bin/bash

testname=$1
bootopt="-m 256M"
mcexecopt=""
testopt=""
kill="n"
dryrun="n"
sleepopt="0.4"
home=$(eval echo \$\{HOME\})
install=${home}/project/os/install

echo Executing ${testname}

case ${testname} in
    rusage011 | rusage012)
	printf "*** Enable debug messages in rusage.h, memory.c, fileobj.c, shmobj.c, process.c by defining DEBUG macro, e.g. #define RUSAGE_DEBUG and then recompile IHK/McKernel.\n"
	printf "*** Install xpmem by git-clone https://github.com/hjelmn/xpmem.\n"
	;;
    rusage10?)
	printf "*** Refer to rusage100.patch to add syscall #900 by editing syscall_list.h and syscall.c and recompile IHK/McKernel.\n"
	;;
    *)
	printf "*** Enable debug messages in rusage.h, memory.c, fileobj.c, shmobj.c, process.c by defining DEBUG macro, e.g. #define RUSAGE_DEBUG and then recompile IHK/McKernel.\n"
	;;
esac
read -p "*** Hit return when ready!" key

case ${testname} in
    rusage005)
	ssh wallaby -c '(cd ${home}/project/src/rusage/verbs; make rdma_wr)'
	bn=verbs/rdma_wr
	;;
    rusage019)
	#ssh wallaby -c '(cd ${home}/project/src/rusage/npb/NPB3.3.1-MZ/NPB3.3-MZ-MPI; make bt-mz CLASS=S NPROCS=2)'
	bn=npb/NPB3.3.1-MZ/NPB3.3-MZ-MPI/bin/bt-mz.S.2
	perl -e 'print "wallaby14\nwallaby15\n"' > ./hostfile
	;;
    rusage021)
	if ! grep /var/log/local6 /etc/rsyslog.conf &>/dev/null; then
	    echo "Insert a line of local6.* /var/log/local6 into /etc/rsyslog.conf"
	    exit 255
	fi
	ssh wallaby bash -c '(cd ${home}/project/src/rusage/npb/NPB3.3.1-MZ/NPB3.3-MZ-MPI; make bt-mz CLASS=S NPROCS=4)'
	bn=npb/NPB3.3.1-MZ/NPB3.3-MZ-MPI/bin/bt-mz.S.4
	perl -e 'print "polaris:2\nkochab:2\n"' > ./hostfile
	;;
    *)
	bn=${testname}
	make clean > /dev/null 2> /dev/null
	make ${bn}
esac

pid=`pidof mcexec`
if [ "${pid}" != "" ]; then
    kill -9 ${pid} > /dev/null 2> /dev/null 
fi

case ${testname} in
    rusage000)
	testopt="0"
	;;
    rusage010)
	testopt="1"
	;;
    rusage020)
	bootopt="-m 256M@0,1G@0"
	testopt="2"
	kill="y"
	;;
    rusage030)
	testopt="3"
	;;
    rusage001)
	cp ${bn} ./file
	kill="n"
	;;
    rusage002)
	mcexecopt="--mpol-shm-premap"
	;;
    rusage003)
	;;
    rusage004)
	cp ${bn} ./file
	;;
    rusage005)
	echo ssh wallaby15.aics-sys.riken.jp ${home}/project/src/verbs/rdma_wr -p 10000&
	read -p "Run rdma_wr on wallaby15 and enter the port number." port
	testopt="-s wallaby15.aics-sys.riken.jp -p ${port}"
	;;
    rusage006)
	mcexecopt="--mpol-shm-premap"
	;;
    rusage007)
	;;
    rusage008)
	cp ${bn} ./file
	;;
    rusage009)
	;;
    rusage011)
	sudo insmod /home/takagi/usr/lib/module/xpmem.ko
	sudo chmod og+rw /dev/xpmem
	dryrun="n"
	kill="n"
	sleepopt="5"
	;;
    rusage012)
	sudo insmod /home/takagi/usr/lib/module/xpmem.ko
	sudo chmod og+rw /dev/xpmem
	dryrun="n"
	kill="n"
	sleepopt="5"
	;;
    rusage013)
	cp ${bn} ./file
	;;
    rusage014)
	cp ${bn} ./file
	;;
    rusage015)
	cp ${bn} ./file
	;;
    rusage016)
	;;
    rusage017)
	cp ${bn} ./file
	;;
    rusage018)
	;;
    rusage019 | rusage021)
	bootopt="-k 1 -m 256M"
	;;
    rusage100)
	;;
    rusage101)
	;;
    rusage102)
	cp ${bn} ./file
	;;
    rusage103)
	bootopt="-m 256M@1"
	;;
    *)
	echo Unknown test case 
	exit 255
esac

if [ ${dryrun} == "y" ]; then
exit
fi

case ${testname} in
    rusage019 | rusage021)
	sudo rm /var/log/local6
	sudo touch /var/log/local6
	sudo chmod 600 /var/log/local6
	sudo systemctl restart rsyslog
	;;
    *)
	;;
esac

case ${testname} in
    rusage019 | rusage021)
	echo sudo ssh wallaby15 ${install}/sbin/mcstop+release.sh &&
	echo sudo ssh wallaby15 ${install}/sbin/mcreboot.sh
	read -p "Boot mckernel on wallaby15." ans
	;;
    *)
	;;
esac
sudo ${install}/sbin/mcstop+release.sh &&
sudo ${install}/sbin/mcreboot.sh ${bootopt}

if [ ${kill} == "y" ]; then
    ${install}/bin/mcexec ${mcexecopt} ./${bn} ${testopt} &
    sleep ${sleepopt}
    sudo ${install}/sbin/ihkosctl 0 kmsg > ./${testname}.log
    pid=`pidof mcexec`
    if [ "${pid}" != "" ]; then
	kill -9 ${pid} > /dev/null 2> /dev/null
    fi
else
    case ${testname} in
	rusage005)
	    ${install}/bin/mcexec ${mcexecopt} ./${bn} ${testopt}
	    #read -p "Run rdma_wr." ans
	    sudo ${install}/sbin/ihkosctl 0 kmsg > ./${testname}.log
	    ;;
	rusage019 | rusage021)
	    echo OMP_NUM_THREADS=2 mpiexec -machinefile ./hostfile ${install}/bin/mcexec ${mcexecopt} ./${bn} ${testopt}
	    read -p "Run ${bn} and hit return." ans
	    sleep 1.5
	    sudo cat /var/log/local6 > ./${testname}.log
	    ;;
	rusage100 | rusage101 | rusage102 | rusage103)
	    ${install}/bin/mcexec ${mcexecopt} ./${bn} ${testopt} > ./${testname}.log
	    echo "================================================" >> ./${testname}.log
	    sudo ${install}/sbin/ihkosctl 0 kmsg >> ./${testname}.log
	    ;;
	*)
	    ${install}/bin/mcexec ${mcexecopt} ./${bn} ${testopt}
	    sudo ${install}/sbin/ihkosctl 0 kmsg > ./${testname}.log
    esac
fi

case ${testname} in
    rusage10?)
	printf "*** Check the ihk_os_getrusage() result (the first part of ${testname}.log) matches with the syscall #900 result (the second part) \n"
	;;

    *)
	printf "*** cat ${testname}.log (kmsg) > ./match.pl to confirm there's no stray add/sub.\n"
	printf "*** Look ${testname}.log (kmsg) to confirm memory_stat_*[*] returned to zero when the last thread exits.\n"
	;;
esac

sudo ${install}/sbin/mcstop+release.sh
