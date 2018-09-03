#!/usr/bin/bash
MYHOME="/work/gg10/e29005"
MCK="${MYHOME}/project/os/install"
MCEXEC=
export DISABLE_UTI=0

stop=0
reset=0
go=0
nodes="c[8194]"

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
    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w ${nodes} \
    sudo mount /work

    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w ${nodes} \
	sudo ${MCK}/sbin/mcstop+release.sh
fi

if [ ${reset} -eq 1 ]; then
    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w ${nodes} \
    sudo mount /work

    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w ${nodes} \
	sudo ${MCK}/sbin/mcreboot.sh -c 2-17,20-35,36-51,52-67 -r 2-5:0+6-9:1+10-13:68+14-17:69+20-23:136+24-27:137+28-31:204+32-35:205+36-39:18+40-43:19+44-47:86+48-51:87+52-55:154+56-59:155+60-63:222+64-67:223 -m 32G@0,12G@1
fi

if [ ${go} -eq 1 ]; then
    > ./log
    for i in {1..10}; do (${MCEXEC} --enable-uti ./CT09 1>/dev/null 2>> ./log); done
    #${MCEXEC} ./CT09
    perl CT11.pl < ./log
fi
