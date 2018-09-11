#!/usr/bin/bash

test_dir=`pwd -P`
mck_dir=${HOME}/project/os/install
uti_dir_lin=${HOME}/project/uti/install_linux
uti_dir_mck=${HOME}/project/uti/install_mckernel

exe=`basename $0 | sed 's/\.sh//'`

stop=0
reboot=0
go=0

interactive=0
pjsub=0
gdb=0
disable_syscall_intercept=0
mck=0
nnodes=2
host_type=wallaby
LASTNODE=15
use_hfi=0
omp_num_threads=4
ppn=4
aio_num_threads=1

while getopts srgc:ml:N:P:o:hGI:ipL: OPT
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
	    N) nnodes=$OPTARG
		;;
	    P) ppn=$OPTARG
		;;
	    o) omp_num_threads=$OPTARG
		;;
	    h) use_hfi=1
		;;
	    G) gdb=1
		;;
	    I) disable_syscall_intercept=$OPTARG
		;;
	    i) interactive=1
		;;
	    p) pjsub=1
		;;
	    L) LASTNODE=$OPTARG
		;;
            *) echo "invalid option -${OPT}" >&2
                exit 1
        esac
done

case $host_type in
    wallaby) hnprefix=wallaby
	;;
    ofp) hnprefix=c
	;;
    *) echo "invalid host_type $host_type"
	exit 1
esac

nprocs=$((ppn * nnodes))
nodes="$hnprefix`echo $(seq -s ",$hnprefix" $(($LASTNODE + 1 - $nnodes)) $LASTNODE)`"

case $host_type in
    wallaby)
	uti_cpu_set_lin=0,16,8,24
	exclude_list=0,16,8,24
	uti_cpu_set_mck=0,16,8,24
	;;
    ofp)
	# vertical cut, excluding phys loaded with Linux tasks
	uti_cpu_set_lin=1,69,137,205,18-19,86-87,154-155,222-223
	exclude_list=0-1,68-69,136-137,204-205,18-19,86-87,154-155,222-223
	#64-67,132-135,200-203,268-271 
	
	uti_cpu_set_mck=1,69,137,205,18-19,86-87,154-155,222-223
	
	# horizontal cut, excluding phys loaded with Linux tasks for mckernel
	#uti_cpu_set_lin=204-271 
	#uti_cpu_set_mck=1-67
	;;
    *) echo "invalid host_type $host_type"
	exit 1
esac

if [ $mck -eq 0 ]; then
    uti_cpu_set_str="export UTI_CPU_SET=$uti_cpu_set_lin"
    i_mpi_pin_processor_exclude_list="export I_MPI_PIN_PROCESSOR_EXCLUDE_LIST=$exclude_list"
else
    uti_cpu_set_str="export UTI_CPU_SET=$uti_cpu_set_mck"
    i_mpi_pin_processor_exclude_list=
fi

if [ ${mck} -eq 1 ]; then
    i_mpi_pin=off
    i_mpi_pin_domain=
    i_mpi_pin_order=
#    if [ $omp_num_threads -eq 1 ]; then
#	# Avoid binding main thread and uti thread to one CPU
	kmp_affinity="export KMP_AFFINITY=disabled" 
#    else
#	# Bind rank to OMP_NUM_THREAD-sized CPU-domain
#	kmp_affinity="export KMP_AFFINITY=granularity=thread,scatter"
#    fi
else
    i_mpi_pin=on
    domain=$omp_num_threads # Use 32 when you want to match mck's -n division
    i_mpi_pin_domain="export I_MPI_PIN_DOMAIN=$domain"
    i_mpi_pin_order="export I_MPI_PIN_ORDER=compact"
    kmp_affinity="export KMP_AFFINITY=granularity=thread,scatter"
fi

echo nprocs=$nprocs nnodes=$nnodes ppn=$ppn nodes=$nodes domain=$domain

if [ ${mck} -eq 1 ]; then
    makeopt="UTI_DIR=$uti_dir_mck"
    use_mck="#PJM -x MCK=$mck_dir"
    mck_mem="#PJM -x MCK_MEM=32G@0,8G@1"
    mcexec="${mck_dir}/bin/mcexec"
    nmcexecthr=$((omp_num_threads + 1 + aio_num_threads * 2 + 2))
    mcexecopt="-n $ppn -t $nmcexecthr" # --uti-use-last-cpu

    if [ ${use_hfi} -eq 1 ]; then
	mcexecopt="--enable-hfi1 $mcexecopt"
    fi

    if [ $disable_syscall_intercept -eq 0 ]; then
	mcexecopt="--enable-uti $mcexecopt"
    fi

else
    offline=`PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes lscpu 2>&1 | dshbak -c | grep Off-line`
    if [ "$offline" != "" ]; then
	echo "Error: Some CPUs are offline: $offline"
	exit
    fi

    makeopt="UTI_DIR=$uti_dir_lin"
    use_mck=
    mck_mem=
    mcexec=
    mcexecopt=
fi

if [ $gdb -eq 1 ]; then
    enable_x="-enable-x"
    gdbcmd="xterm -display localhost:11 -hold -e gdb -ex run --args"
fi

if [ $interactive -eq 1 ]; then
    i_mpi_hydra_bootstrap_exec=
    i_mpi_hydra_bootstrap=
    hosts=
    ssh=
else
#    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes bash -c \'if \[ \"\`cat /etc/mtab \| while read line\; do cut -d\" \" -f 2\; done \| grep /work\`\" == \"\" \]\; then sudo mount /work\; fi\'
    i_mpi_hydra_bootstrap_exec="export I_MPI_HYDRA_BOOTSTRAP_EXEC=/usr/bin/ssh"
    i_mpi_hydra_bootstrap="export I_MPI_HYDRA_BOOTSTRAP=ssh"
    hosts="-hosts $nodes"
    ssh="ssh -A $(echo $nodes | cut -d',' -f1)"
fi

case $host_type in
    wallaby)
	i_mpi_fabrics="export I_MPI_FABRICS=shm:dapl"
	i_mpi_tmi_provider=

	opt_dir=/opt/intel	
	impiver=2018.3.222 # 1.163, 2.199, 3.222
	;;
    ofp)
	i_mpi_fabrics="export I_MPI_FABRICS=shm:tmi"
	i_mpi_tmi_provider="export I_MPI_TMI_PROVIDER=psm2"

	if [ $interactive -eq 1 ]; then
	    opt_dir=/opt/intel
	else
	    opt_dir=/home/opt/local/cores/intel
	fi
	impiver=2018.1.163 # 1.163, 2.199, 3.222
	;;
    *) echo "invalid host_type $host_type"
	exit 1
esac

# If using ssh
if [ $pjsub -eq 0 ] && [ $interactive -eq 0 ]; then
    compilervars=". ${opt_dir}/compilers_and_libraries_${impiver}/linux/bin/compilervars.sh intel64"
else
    compilervars=
fi

if [ ${stop} -eq 1 ]; then
    if [ ${mck} -eq 1 ]; then
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
	    /usr/sbin/pidof mcexec \| xargs -r sudo kill -9
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
	    /usr/sbin/pidof $exe \| xargs -r sudo kill -9
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
	    sudo ${mck_dir}/sbin/mcstop+release.sh
    else
	:
    fi
fi

if [ ${reboot} -eq 1 ]; then
    if [ ${mck} -eq 1 ]; then
	case $host_type in
	    wallaby) hnprefix=wallaby
		PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes sudo ${mck_dir}/sbin/mcreboot.sh -h -O -c 1-7,17-23,9-15,25-31 -r 1-7:0+17-23:16+9-15:8+25-31:24 -m 10G@0,10G@1
		#PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes sudo ${mck_dir}/sbin/mcreboot.sh -h -O -c 1-4 -r 1-4:0 -m 10G@0,10G@1
		;;
	    ofp)
		# -h: Prevent unnessary CPU resource division for KNL 
		PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
		    sudo ${mck_dir}/sbin/mcreboot.sh -h -O -c 2-17,70-85,138-153,206-221,20-35,88-103,156-171,224-239,36-51,104-119,172-187,240-255,52-67,120-135,188-203,256-271 -r 2-5,70-73,138-141,206-209:0+6-9,74-77,142-145,210-213:1+10-13,78-81,146-149,214-217:68+14-17,82-85,150-153,218-221:69+20-23,88-91,156-159,224-227:136+24-27,92-95,160-163,228-231:137+28-31,96-99,164-167,232-235:204+32-35,100-103,168-171,236-239:205+36-39,104-107,172-175,240-243:18+40-43,108-111,176-179,244-247:19+44-47,112-115,180-183,248-251:86+48-51,116-119,184-187,252-255:87+52-55,120-123,188-191,256-259:154+56-59,124-127,192-195,260-263:155+60-63,128-131,196-199,264-267:222+64-67,132-135,200-203,268-271:223 -m 32G@0,12G@1
		;;
	    *) echo "invalid host_type $host_type"
		exit 1
	esac
    else
	:
    fi
fi

(
cat <<EOF
#!/bin/sh

#PJM -L rscgrp=$rg
#PJM -L node=$nnodes
#PJM --mpi proc=$nprocs
#PJM -L elapse=$elapse
#PJM -L proc-crproc=16384 
#PJM -g gg10
#PJM -j
#PJM -s
$use_mck
$mck_mem

$i_mpi_hydra_bootstrap_exec
$i_mpi_hydra_bootstrap

export OMP_NUM_THREADS=$omp_num_threads
#export OMP_STACKSIZE=64M
export KMP_BLOCKTIME=1

$uti_cpu_set_str
export I_MPI_PIN=$i_mpi_pin
$i_mpi_pin_processor_exclude_list
$i_mpi_pin_domain
$i_mpi_pin_order
$kmp_affinity

export HFI_NO_CPUAFFINITY=1
export I_MPI_COLL_INTRANODE_SHM_THRESHOLD=4194304
$i_mpi_fabrics
$i_mpi_tmi_provider
export I_MPI_FALLBACK=0
export PSM2_RCVTHREAD=0
export PSM2_MQ_RNDV_HFI_WINDOW=4194304
export PSM2_MQ_EAGER_SDMA_SZ=65536
export PSM2_MQ_RNDV_HFI_THRESH=200000

export MCKERNEL_RLIMIT_STACK=32M,16G
export KMP_STACKSIZE=64m
#export KMP_HW_SUBSET=64c,1t

export I_MPI_ASYNC_PROGRESS=off

#export I_MPI_STATS=native:20,ipm
#export I_MPI_STATS=ipm
#export I_MPI_DEBUG=4
#export I_MPI_HYDRA_DEBUG=on

ulimit -c unlimited 

$compilervars
mpiexec.hydra -n $nprocs -ppn $ppn $hosts $ilpopt $enable_x $gdbcmd $mcexec $mcexecopt ${test_dir}/$exe -I $disable_syscall_intercept -p $ppn -t $aio_num_threads
#$gdbcmd $mcexec $mcexecopt ${test_dir}/$exe -I $disable_syscall_intercept -p $ppn -t $aio_num_threads
#-l

EOF
) > ./job.sh
chmod u+x ./job.sh

if [ ${go} -eq 1 ]; then
    if [ $pjsub -eq 1 ]; then
	pjsub ./job.sh
    else
	if [ $interactive -eq 0 ]; then
	    eval $compilervars
	fi
	make $makeopt ./$exe
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
	    /usr/sbin/pidof $exe \| xargs -r sudo kill -9
	$ssh ${test_dir}/job.sh
    fi
fi
