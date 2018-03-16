#!/usr/bin/bash

bn=`basename $0`
fn=`echo $bn | sed 's/.sh//'`

stop=0
reboot=0
go=0
mck=0
NNODES=1
NPROC=$((16 * NNODES))
LASTNODE=8199
export OMP_NUM_THREADS=2
export KMP_BLOCKTIME=1
export PSM2_RCVTHREAD=0

while getopts srgmN:P:L: OPT
do
        case ${OPT} in
	    s) stop=1
		;;
            r) reboot=1
                ;;
            g) go=1
                ;;
            m) mck=1
                ;;
	    N) NNODES=$OPTARG
		;;
	    P) NPROC=$OPTARG
		;;
	    L) LASTNODE=$OPTARG
		;;
            *) echo "invalid option -${OPT}" >&2
                exit 1
        esac
done

MPILIB=/home/opt/local/cores/intel/impi/2018.1.163/intel64
ABS_SRCDIR=${HOME}/project/os/mckernel/test/uti
MCK=${HOME}/project/os/install

NODES=`echo $(seq -s ",c" $(($LASTNODE + 1 - $NNODES)) $LASTNODE) | sed 's/^/c/'`
PPN=$((NPROC / NNODES))
echo NPROC=$NPROC NNODES=$NNODES PPN=$PPN NODES=$NODES

if [ ${mck} -eq 1 ]; then
    MCEXEC="${MCK}/bin/mcexec"
    nmcexecthr=$((256 / PPN + 4))
    mcexecopt="-n $PPN -t $nmcexecthr -m 1 $mcexecopt"
else
    MCEXEC=
    mcexecopt=
fi

if [ ${stop} -eq 1 ]; then
    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $NODES \
	sudo mount /work

    if [ ${mck} -eq 1 ]; then
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $NODES \
	    /sbin/pidof mcexec \| xargs -r kill -9
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $NODES \
	    sudo ${MCK}/sbin/mcstop+release.sh
    else
	:
    fi
fi

if [ ${reboot} -eq 1 ]; then
    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $NODES \
    sudo mount /work

    if [ ${mck} -eq 1 ]; then
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $NODES \
	    sudo ${MCK}/sbin/mcreboot.sh -c 2-17,70-85,138-153,206-221,20-35,88-103,156-171,224-239,36-51,104-119,172-187,240-255,52-67,120-135,188-203,256-271 -r 2-5,70-73,138-141,206-209:0+6-9,74-77,142-145,210-213:1+10-13,78-81,146-149,214-217:68+14-17,82-85,150-153,218-221:69+20-23,88-91,156-159,224-227:136+24-27,92-95,160-163,228-231:137+28-31,96-99,164-167,232-235:204+32-35,100-103,168-171,236-239:205+36-39,104-107,172-175,240-243:18+40-43,108-111,176-179,244-247:19+44-47,112-115,180-183,248-251:86+48-51,116-119,184-187,252-255:87+52-55,120-123,188-191,256-259:154+56-59,124-127,192-195,260-263:155+60-63,128-131,196-199,264-267:222+64-67,132-135,200-203,268-271:223 -m 32G@0,12G@1
    else
	:
    fi
fi

if [ ${go} -eq 1 ]; then
    cd $ABS_SRCDIR
    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $NODES \
	ulimit -u 16384; 
    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $NODES \
	ulimit -s unlimited

    export I_MPI_HYDRA_BOOTSTRAP_EXEC=/usr/bin/ssh
    export I_MPI_HYDRA_BOOTSTRAP=ssh

    if [ ${mck} -eq 1 ]; then
	export I_MPI_PIN=off
    else
	export I_MPI_PIN=on
    fi
    export HFI_NO_CPUAFFINITY=1
    export I_MPI_COLL_INTRANODE_SHM_THRESHOLD=4194304
    export I_MPI_FABRICS=shm:tmi
    export PSM2_RCVTHREAD=0
    export I_MPI_TMI_PROVIDER=psm2
    export I_MPI_FALLBACK=0
    export PSM2_MQ_RNDV_HFI_WINDOW=4194304
    export PSM2_MQ_EAGER_SDMA_SZ=65536
    export PSM2_MQ_RNDV_HFI_THRESH=200000
    
    export MCKERNEL_RLIMIT_STACK=32M,16G
    export KMP_STACKSIZE=64m
    export KMP_AFFINITY=granularity=thread,scatter
    export KMP_HW_SUBSET=$((64 / PPN))c,1t
    export I_MPI_ASYNC_PROGRESS=${async}
    
    . /home/opt/local/cores/intel/compilers_and_libraries_2018.1.163/linux/bin/compilervars.sh intel64
    mpiexec.hydra -l -n $NPROC -ppn $PPN -hosts $NODES bash -c '. /home/opt/local/cores/intel/compilers_and_libraries_2018.1.163/linux/bin/compilervars.sh intel64; '"$MCEXEC $mcexecopt ./$fn"''
fi

