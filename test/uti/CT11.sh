#!/usr/bin/bash
MYHOME="/work/gg10/e29005"
MCK="${MYHOME}/project/os/install"
MCEXEC=""
export DISABLE_UTI=0

stop=0
reset=0
go=0

while getopts srgmd OPT
do
        case ${OPT} in
	    s) stop=1
		;;
            r) reset=1
                ;;
            g) go=1
                ;;
            m) MCEXEC="${MCK}/bin/mcexec"
                ;;
            d) export DISABLE_UTI=1
                ;;
            *) echo "invalid option -${OPT}" >&2
                exit 1
        esac
done

if [ ${stop} -eq 1 ]; then
    sudo mount /work

    sudo rm /dev/hello
    sudo rmmod "driver/hello.ko"
    sudo ${MCK}/sbin/mcstop+release.sh
fi

if [ ${reset} -eq 1 ]; then
    sudo mount /work

    sudo insmod "driver/hello.ko"
    major=`grep hello /proc/devices | cut -d' ' -f 1`
    sudo mknod /dev/hello c $major 0
    sudo chmod og+rw /dev/hello
    
    sudo ${MCK}/sbin/mcreboot.sh -c 2-17,70-85,138-153,206-221,20-35,88-103,156-171,224-239,36-51,104-119,172-187,240-255,52-67,120-135,188-203,256-271 -r 2-5,70-73,138-141,206-209:0+6-9,74-77,142-145,210-213:1+10-13,78-81,146-149,214-217:68+14-17,82-85,150-153,218-221:69+20-23,88-91,156-159,224-227:136+24-27,92-95,160-163,228-231:137+28-31,96-99,164-167,232-235:204+32-35,100-103,168-171,236-239:205+36-39,104-107,172-175,240-243:18+40-43,108-111,176-179,244-247:19+44-47,112-115,180-183,248-251:86+48-51,116-119,184-187,252-255:87+52-55,120-123,188-191,256-259:154+56-59,124-127,192-195,260-263:155+60-63,128-131,196-199,264-267:222+64-67,132-135,200-203,268-271:223 -m 32G@0,12G@1
fi

if [ ${go} -eq 1 ]; then
make
> ./log
for i in {1..10}; do (${MCEXEC} ./CT11 1>/dev/null 2>> ./log); done
perl CT11.pl < ./log
#${MCEXEC} ./CT11
fi

