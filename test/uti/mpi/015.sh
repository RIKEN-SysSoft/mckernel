#!/usr/bin/bash

#!/usr/bin/bash -x

MYHOME=/work/gg10/e29005
UTI_MPI_TOP=${MYHOME}/project/os/mckernel/test/uti/mpi

mck_dir=${MYHOME}/project/os/install

exe=`basename $0 | sed 's/\.sh//'`

stop=0
reboot=0
go=0

async=0
mck=0
nnodes=2
LASTNODE=8200
ndoubles=16 #2^12-15
add_rate="1.0"
disable_uti=0
omp_num_threads=1
ppn=16 #16
async_progress_pin=64,132,200,268,65,133,201,269,66,134,202,270,67,135,203,271
lpp=4 # logical-per-physical
ncpu_mt=256 # number of CPUs for main-thread
myasync=1
use_hfi=0

while getopts srga:c:n:md:l:N:P:o:A:R: OPT
do
        case ${OPT} in
            s) stop=1
                ;;
            r) reboot=1
                ;;
	    g) go=1
		;;
	    a) async=$OPTARG
		;;
	    n) ndoubles=$OPTARG
		;;
            m) mck=1
                ;;
            d) disable_uti=$OPTARG
                ;;
	    N) nnodes=$OPTARG
		;;
	    P) ppn=$OPTARG
		;;
	    o) omp_num_threads=$OPTARG
		;;
	    A) myasync=$OPTARG
		;;
	    R) add_rate=$OPTARG
		;;
            *) echo "invalid option -${OPT}" >&2
                exit 1
        esac
done

nprocs=$((ppn * nnodes))
nodes=`echo $(seq -s ",c" $(($LASTNODE + 1 - $nnodes)) $LASTNODE) | sed 's/^/c/'`
echo nprocs=$nprocs nnodes=$nnodes ppn=$ppn nodes=$nodes

PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes bash -c \'if \[ \"\`cat /etc/mtab \| while read line\; do cut -d\" \" -f 2\; done \| grep /work\`\" == \"\" \]\; then sudo mount /work\; fi\'

if [ $disable_uti -eq 1 ]; then
    export DISABLE_UTI=1
else
    unset DISABLE_UTI
fi

if [ ${mck} -eq 1 ]; then
    mcexec="${mck_dir}/bin/mcexec"
    nmcexecthr=$((omp_num_threads + 4))
    mcexecopt="--uti-thread-rank=$uti_thread_rank"
    if [ ${use_hfi} -eq 1 ]; then
	mcexecopt="--enable-hfi1 $mcexecopt"
    fi
    mcexecopt="-n $ppn -t $nmcexecthr $mcexecopt"
else
    mcexec=
    mcexecopt=
fi

if [ ${mck} -eq 1 ]; then
    i_mpi_pin=off
    i_mpi_pin_domain=
    i_mpi_pin_order=
else
    # Let each domain have all logical cores and use KMP_AFFINITY=scatter if you want to use only physical cores
    i_mpi_pin=on
    if [ $((omp_num_threads * lpp * ppn)) -le $ncpu_mt ]; then
	domain=$((omp_num_threads * lpp)) # Prefer physical but adjacent physicals share L1
    else
	domain=$((ncpu_mt / ppn)) # Use logical as well
    fi 
    i_mpi_pin_domain="export I_MPI_PIN_DOMAIN=$domain"
    i_mpi_pin_order="export I_MPI_PIN_ORDER=compact"
fi

if [[ ($async -eq 1  && "$async_progress_pin" != "" ) || $myasync -eq 1 ]]; then
    i_mpi_async_progress_pin="export I_MPI_ASYNC_PROGRESS_PIN=$async_progress_pin"
else
    i_mpi_async_progress_pin=
fi

if [ ${stop} -eq 1 ]; then
    if [ ${mck} -eq 1 ]; then
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes sudo ${mck_dir}/sbin/mcstop+release.sh
    else
	:
    fi
fi

if [ ${reboot} -eq 1 ]; then
    if [ ${mck} -eq 1 ]; then
	if hostname  | grep ofp &>/dev/null; then
	    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes sudo ${mck_dir}/sbin/mcreboot.sh -s -c 2-17,70-85,138-153,206-221,20-35,88-103,156-171,224-239,36-51,104-119,172-187,240-255,52-67,120-135,188-203,256-271 -r 2-5,70-73,138-141,206-209:0+6-9,74-77,142-145,210-213:1+10-13,78-81,146-149,214-217:68+14-17,82-85,150-153,218-221:69+20-23,88-91,156-159,224-227:136+24-27,92-95,160-163,228-231:137+28-31,96-99,164-167,232-235:204+32-35,100-103,168-171,236-239:205+36-39,104-107,172-175,240-243:18+40-43,108-111,176-179,244-247:19+44-47,112-115,180-183,248-251:86+48-51,116-119,184-187,252-255:87+52-55,120-123,188-191,256-259:154+56-59,124-127,192-195,260-263:155+60-63,128-131,196-199,264-267:222+64-67,132-135,200-203,268-271:223 -m 32G@0,12G@1
	else
	    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes sudo ${mck_dir}/sbin/mcreboot.sh -s -c 1-15,65-79,129-143,193-207,17-31,81-95,145-159,209-223,33-47,97-111,161-175,225-239,49-63,113-127,177-191,241-255 -r 1-15:0+65-79:64+129-143:128+193-207:192+17-31:16+81-95:80+145-159:144+209-223:208+33-47:32+97-111:96+161-175:160+225-239:224+49-63:48+113-127:112+177-191:176+241-255:240 -m 12G@0,12G@1,12G@2,12G@3,3920M@4,3920M@5,3920M@6,3920M@7
	fi
    else
	:
    fi
fi

cd ${UTI_MPI_TOP}
(
cat <<EOF
#!/bin/sh

export I_MPI_HYDRA_BOOTSTRAP_EXEC=/usr/bin/ssh
export I_MPI_HYDRA_BOOTSTRAP=ssh

export OMP_NUM_THREADS=$omp_num_threads
#export OMP_STACKSIZE=64M
export KMP_BLOCKTIME=1
export PSM2_RCVTHREAD=0

export I_MPI_PIN=$i_mpi_pin
$i_mpi_pin_domain
$i_mpi_pin_order

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
#export KMP_HW_SUBSET=64c,1t

export I_MPI_ASYNC_PROGRESS=$async
$i_mpi_async_progress_pin
export MY_ASYNC_PROGRESS=$myasync

#export I_MPI_STATS=native:20,ipm
#export I_MPI_STATS=ipm
#export I_MPI_DEBUG=4
#export I_MPI_HYDRA_DEBUG=on

mpiexec.hydra -l -n $nprocs -ppn $ppn -hosts $nodes $ilpopt $mcexec $mcexecopt ./$exe --ppn $ppn -d $ndoubles -R $add_rate

EOF
) > ./job.sh
chmod u+x ./job.sh

if [ ${go} -eq 1 ]; then
    cd ${UTI_MPI_TOP}
    if [ $mck -eq 1 ]; then
	make $exe
    else
	. /home/opt/local/cores/intel/compilers_and_libraries_2018.1.163/linux/bin/compilervars.sh intel64
	make CC=mpiicc $exe
    fi
    ./job.sh
fi



