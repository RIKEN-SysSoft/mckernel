#!/usr/bin/bash

#!/usr/bin/bash -x

MYHOME=$HOME
UTI_MPI_TOP=${MYHOME}/project/os/mckernel/test/uti/mpi

MCK=${MYHOME}/project/os/install
unset DISABLE_UTI

cmdline="./008"

stop=0
reboot=0
go=0

mck=0
nloops=1

while getopts srgac:n:mdl: OPT
do
        case ${OPT} in
            s) stop=1
                ;;
            r) reboot=1
                ;;
	    g) go=1
		;;
	    a) async=1
		;;
	    c) cmdline=$OPTARG
		;;
	    n) ndoubles=$OPTARG
		;;
            m) 
		mck=1
                ;;
            d) export DISABLE_UTI=1
                ;;
	    l) nloops=$OPTARG
		;;
            *) echo "invalid option -${OPT}" >&2
                exit 1
        esac
done

if [ ${mck} -eq 1 ]; then
    MCEXEC="${MCK}/bin/mcexec"
else
    MCEXEC=
fi

if [ ${stop} -eq 1 ]; then
    if [ ${mck} -eq 1 ]; then
	    sudo ${MCK}/sbin/mcstop+release.sh
    else
	:
    fi
fi

if [ ${reboot} -eq 1 ]; then
    if [ ${mck} -eq 1 ]; then
	if hostname  | grep ofp &>/dev/null; then
	    sudo ${MCK}/sbin/mcreboot.sh -s -c 2-17,70-85,138-153,206-221,20-35,88-103,156-171,224-239,36-51,104-119,172-187,240-255,52-67,120-135,188-203,256-271 -r 2-5,70-73,138-141,206-209:0+6-9,74-77,142-145,210-213:1+10-13,78-81,146-149,214-217:68+14-17,82-85,150-153,218-221:69+20-23,88-91,156-159,224-227:136+24-27,92-95,160-163,228-231:137+28-31,96-99,164-167,232-235:204+32-35,100-103,168-171,236-239:205+36-39,104-107,172-175,240-243:18+40-43,108-111,176-179,244-247:19+44-47,112-115,180-183,248-251:86+48-51,116-119,184-187,252-255:87+52-55,120-123,188-191,256-259:154+56-59,124-127,192-195,260-263:155+60-63,128-131,196-199,264-267:222+64-67,132-135,200-203,268-271:223 -m 32G@0,12G@1
	else
	    sudo ${MCK}/sbin/mcreboot.sh -s -c 1-15,65-79,129-143,193-207,17-31,81-95,145-159,209-223,33-47,97-111,161-175,225-239,49-63,113-127,177-191,241-255 -r 1-15:0+65-79:64+129-143:128+193-207:192+17-31:16+81-95:80+145-159:144+209-223:208+33-47:32+97-111:96+161-175:160+225-239:224+49-63:48+113-127:112+177-191:176+241-255:240 -m 12G@0,12G@1,12G@2,12G@3,3920M@4,3920M@5,3920M@6,3920M@7
	fi
    else
	:
    fi
fi

if [ ${go} -eq 1 ]; then
    cd ${UTI_MPI_TOP}
    make CC=gcc 008
    for i in `seq 1 ${nloops}`; do
	rm -f psm2-demo-server-epid-*
	#PSM2_RCVTHREAD=0 PMI_RANK=0 DISABLE_UTI=1 ${MCK}/bin/mcexec --enable-uti taskset -c 2 ./008 --ppn 1 &
	PSM2_RCVTHREAD=0 PMI_RANK=1 DISABLE_UTI=0 ${MCK}/bin/mcexec --enable-uti taskset -c 3 ./008 --ppn 1
	#wait
	echo =====;
	echo $i;
	echo =====; i=$((i+1));
	#sleep 2
    done
fi



