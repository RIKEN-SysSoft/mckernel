#!/bin/sh

source ${HOME}/.mck_test_config

if [ $# -lt 1 ]; then
        echo "Error: too few arguments."
        echo "usage: `basename $0` <test_id>"
fi

test_id=$1

pagesize=$(getconf PAGESIZE)
case $pagesize in
    4096) base_name="${test_id}_4K"
	;;
    65536) base_name="${test_id}_64K"
	;;
    *) echo "Error: Unknown page size"
	exit 1
	;;
esac

init="init/${base_name}.init"

if [ ! -e $init ]; then
    echo "$init not found"
    exit 1
fi
source $init

# kill mcexec
pidof 'mcexec ' | xargs -r kill -9

# stop mckernel
echo "sudo ${MCK_DIR}/sbin/mcstop+release.sh"
sudo ${MCK_DIR}/sbin/mcstop+release.sh

# boot mckernel
echo "${MCK_DIR}/sbin/mcreboot.sh ${BOOTPARAM}"
sudo ${MCK_DIR}/sbin/mcreboot.sh ${BOOTPARAM}

if [ ! -e "/dev/mcos0" ]; then
	echo "Error: failed to mcreboot"
	exit 1
fi

# run test program
echo "${MCK_DIR}/bin/mcexec ${MCEXECOPT} ./$base_name"
${MCK_DIR}/bin/mcexec ${MCEXECOPT} ./$base_name

ret=$?
if [ $ret == 0 ]; then
	echo "${MCK_DIR}/sbin/ihkosctl 0 kmsg"
	sudo ${MCK_DIR}/sbin/ihkosctl 0 kmsg
else
        echo "Error: mcexec returned $ret"
fi

fini="fini/${base_name}.fini"
if [ -e $fini ]; then
    source $fini
fi

if [ $ret == 0 ]; then
	exit 0
else
        exit 1
fi

