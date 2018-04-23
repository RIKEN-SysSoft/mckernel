#!/usr/bin/bash -x
MYHOME="/work/gg10/e29005"
MCK="${MYHOME}/project/os/install"
MCEXECOPT="--enable-uti"
export DISABLE_UTI=0

stop=0
reset=0
go=0
mck=0;
loop=0
nodes="c[8195]"
NPROC=8

while getopts srglamd OPT
do
        case ${OPT} in
	    s) stop=1
		;;
            r) reset=1
                ;;
            g) go=1
                ;;
	    l) loop=1
		;;
            m) 
		mck=1
                ;;
            d) export DISABLE_UTI=1
                ;;
            *) echo "invalid option -${OPT}" >&2
                exit 1
        esac
done


if [ ${mck} -eq 1 ]; then
    MCEXEC="${MCK}/bin/mcexec"
    cpus="0-7"
    NUMACTL=
else
    MCEXEC=
    cpus="2-9"
    NUMACTL="numactl -C $cpus"
fi

if [ ${stop} -eq 1 ]; then
    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w ${nodes} \
    sudo mount /work

    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w ${nodes} \
	sudo ${MCK}/sbin/mcstop+release.sh
fi

if [ ${reset} -eq 1 ]; then
    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w ${nodes} \
    sudo mount /work

    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w ${nodes} \
	sudo ${MCK}/sbin/mcreboot.sh `${HOME}/project/src/tools/cpus.pl $NPROC` -m 32G@0,12G@1
    #sudo ${MCK}/sbin/mcreboot.sh -c 2-17,20-35,36-51,52-67 -r 2-5:0+6-9:1+10-13:68+14-17:69+20-23:136+24-27:137+28-31:204+32-35:205+36-39:18+40-43:19+44-47:86+48-51:87+52-55:154+56-59:155+60-63:222+64-67:223 -m 32G@0,12G@1
fi

if [ ${go} -eq 1 ]; then
    cd $MYHOME/project/os/mckernel/test/uti
    rm -f ./CT28
    make -DNPROC=$NPROC

    if [ ${loop} -eq 1 ]; then
	> ./log
	for i in {1..10}; do (${MCEXEC} ${MCEXECOPT} $NUMACTL ./CT28 1> ./log1 2>> ./log); done
	perl CT11.pl < ./log
    else
	${MCEXEC} ${MCEXECOPT} $NUMACTL ./CT28
    fi
fi
