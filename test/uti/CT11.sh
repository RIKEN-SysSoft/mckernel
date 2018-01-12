#!/usr/bin/bash
MYHOME="/work/gg10/e29005"
MCK="${MYHOME}/project/os/install"
MCEXEC=""
export DISABLE_UTI=0
use_mck=0
dry=0

while getopts mdn OPT
do
        case ${OPT} in
            m) MCEXEC="${MCK}/bin/mcexec"
                ;;
            d) export DISABLE_UTI=1
                ;;
	    n) dry=1
		;;
            *) echo "invalid option -${OPT}" >&2
                exit 1
        esac
done

sudo insmod "driver/hello.ko"
major=`grep hello /proc/devices | cut -d' ' -f 1`
sudo mknod /dev/hello c $major 0
sudo chmod og+rw /dev/hello

if [ $dry -ne 1 ]; then
    > ./log
    for i in {1..10}; do (${MCEXEC} ./CT11 1>/dev/null 2>> ./log); done
    perl CT11.pl < ./log
fi

sudo rm /dev/hello
sudo rmmod "driver/hello.ko"
