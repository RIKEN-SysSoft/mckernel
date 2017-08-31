#!/usr/bin/bash

testname=$1
bootopt="-m 256M"
mcexecopt=""
testopt=""
kill="n"
dryrun="n"
sleepopt="0.4"
home=$(eval echo \$\{HOME\})
install=${home}/ppos
rusage=work/rusage/for_ql
walb=wallaby14

echo Executing ${testname}

case ${testname} in
    rusage005)
	#ssh wallaby -c '(cd ${home}/${rusage}/verbs; make rdma_wr)'
	bn=verbs/rdma_wr
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
    rusage010)
	testopt="1"
	;;
    rusage005)
	ssh ${walb}.aics-sys.riken.jp "${home}/${rusage}/verbs/rdma_wr -p 9999" > ${testname}_rcvside.txt &
	echo "Running 'rdma_wr -p 9999' on ${walb}..."
	read -p "please enter to go on."
	port=9999
	testopt="-s ${walb}.aics-sys.riken.jp -p ${port}"
	;;
    rusage008)
	cp ${bn} ./file
	;;
    rusage009)
	;;
    rusage011)
	if [ `lsmod | grep xpmem | wc -l` -eq 0 ]; then
		sudo insmod /home/satoken/install/xpmem-master/lib/module/xpmem.ko
		sudo chmod og+rw /dev/xpmem
	fi
	dryrun="n"
	kill="n"
	sleepopt="5"
	;;
    *)
	echo Unknown test case 
	exit 255
esac

if [ ${dryrun} == "y" ]; then
exit
fi

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
		echo "**** message of sender side **************************"
	    ${install}/bin/mcexec ${mcexecopt} ./${bn} ${testopt}
		echo "******************************************************"
		
		echo "**** message of reciever side ************************"
		cat ${testname}_rcvside.txt
		echo "******************************************************"
	    #read -p "Run rdma_wr." ans
	    sudo ${install}/sbin/ihkosctl 0 kmsg > ./${testname}.log
	    ;;
	*)
	    ${install}/bin/mcexec ${mcexecopt} ./${bn} ${testopt}
	    sudo ${install}/sbin/ihkosctl 0 kmsg > ./${testname}.log
    esac
fi

sudo ${install}/sbin/mcstop+release.sh
