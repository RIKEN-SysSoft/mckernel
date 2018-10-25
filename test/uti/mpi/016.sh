#!/usr/bin/bash

#!/usr/bin/bash -x

MYHOME=/home/e29005
test_dir=`pwd -P`
mck_dir=${MYHOME}/project/os/install
uti_dir_lin=${MYHOME}/project/uti/install_linux
uti_dir_mck=${MYHOME}/project/uti/install_mckernel

exe=`basename $0`
exe=${exe/.sh/}

stop=0
reboot=0
go=0

jobtype=ssh # interactive or pjsub or ssh
gdb=0
disable_syscall_intercept=0
mck=0
nnodes=2
LASTNODE=8200
use_hfi=0
omp_num_threads=32
ppn=4
mpitype=mvapich

while getopts srgc:ml:N:P:o:hGI:j:L:M: OPT
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
	    j) jobtype=$OPTARG
		;;
	    p) pjsub=1
		;;
	    L) LASTNODE=$OPTARG
		;;
	    M) mpitype=$OPTARG
		;;
            \?) exit 1
		;;
        esac
done

nprocs=$((ppn * nnodes))
nodes=`echo $(seq -s ",c" $(($LASTNODE + 1 - $nnodes)) $LASTNODE) | sed 's/^/c/'`

# vertical cut, excluding phys loaded with Linux tasks
uti_cpu_set_lin=1,69,137,205,18-19,86-87,154-155,222-223
exclude_list=0-1,68-69,136-137,204-205,18-19,86-87,154-155,222-223
#64-67,132-135,200-203,268-271 

uti_cpu_set_mck=1,69,137,205,18-19,86-87,154-155,222-223

# horizontal cut, excluding phys loaded with Linux tasks for mckernel
#uti_cpu_set_lin=204-271 
#uti_cpu_set_mck=1-67

if [ $mck -eq 1 ]; then
    uti_cpu_set="export UTI_CPU_SET=$uti_cpu_set_mck"
else
    uti_cpu_set="export UTI_CPU_SET=$uti_cpu_set_lin"
fi

if [ ${mck} -eq 1 ]; then
    case $mpitype in
	intel)
	    # Bind by "mcexec -n"
	    i_mpi_pin_processor_exclude_list=
	    i_mpi_pin=off
	    i_mpi_pin_domain=
	    i_mpi_pin_order=
	    ;;
	mvapich)
	    # Bind by "MV2_CPU_MAPPING"
	    # CPU ordering of McKernel is different than Linux.
	    # That is, using <Quadrant, Physical, Logical> representation, 
	    # ordering is like this:
	    # <0,0,0>, ..., <0,15,0>, <0,0,1>, 
	    mv2_cpu_mapping="export MV2_CPU_MAPPING=0-7,16-23,32-39,48-55:8-15,24-31,40-47,56-63:64-71,80-87,96-103,112-119:72-79,88-95,104-111,120-127:128-135,144-151,160-167,176-183:136-143,152-159,168-175,184-191:192-199,208-215,224-231,240-247:200-207,216-223,232-239,248-255"
	    ;;
    esac
else
    case $mpitype in
	intel)
	    # Bind by "I_MPI_PIN_*"
	    i_mpi_pin_processor_exclude_list="export I_MPI_PIN_PROCESSOR_EXCLUDE_LIST=$exclude_list"
	    i_mpi_pin=on
	    domain=$omp_num_threads # Use 32 when you want to match mck's -n division
	    i_mpi_pin_domain="export I_MPI_PIN_DOMAIN=$domain"
	    i_mpi_pin_order="export I_MPI_PIN_ORDER=compact"
	    ;;
	mvapich)
	    # Bind by "MV2_CPU_MAPPING"
	    # excluding CPUS in exclude_list (0-1,68-69,136-137,204-205,18-19,86-87,154-155,222-223)
	    # perl -e '@ss = (2,20,36,52); foreach $s (@ss) { if($s!=$ss[0]){print ":";}for ($j=0;$j<16;$j+=8) {if($j!=0){print ":"}for ($i=$s;$i<272;$i+=68){if($i!=$s){print ",";} printf("%d-%d", $j+$i, $j+$i+7);}}}print "\n"'
	    mv2_cpu_mapping="export MV2_CPU_MAPPING=2-9,70-77,138-145,206-213:10-17,78-85,146-153,214-221:20-27,88-95,156-163,224-231:28-35,96-103,164-171,232-239:36-43,104-111,172-179,240-247:44-51,112-119,180-187,248-255:52-59,120-127,188-195,256-263:60-67,128-135,196-203,264-271"
	    ;;
    esac
fi

if [ ${mck} -eq 1 ]; then
    # Bind by "mcexec -n"
    #    if [ $omp_num_threads -eq 1 ]; then
    #	# Avoid binding main thread and uti thread to one CPU
    kmp_affinity="export KMP_AFFINITY=disabled" 
    #    else
    #	# Bind rank to OMP_NUM_THREAD-sized CPU-domain
    #	kmp_affinity="export KMP_AFFINITY=granularity=thread,scatter"
    #    fi
else
    kmp_affinity="export KMP_AFFINITY=granularity=thread,scatter"
fi

echo nprocs=$nprocs nnodes=$nnodes ppn=$ppn nodes=$nodes domain=$domain

if [ $gdb -eq 1 ]; then
    enable_x="-enable-x"
    gdbcmd="xterm -display localhost:11 -hold -e gdb -ex run --args"
fi

case $mpitype in
    intel)
	makeopt="CC=mpiicc"
	mpiexec="mpiexec.hydra"
	;;
    mvapich)
	mpi_dir=${HOME}/project/src/mvapich/install
	makeopt="CC=${mpi_dir}/bin/mpicc"
	mpiexec="${mpi_dir}/bin/mpiexec.hydra"
	;;
esac

# compilervars for compile
case $jobtype in
    interactive)
	opt_dir=/opt/intel
	compilervars_compile=". ${opt_dir}/compilers_and_libraries_2018.2.199/linux/bin/compilervars.sh intel64"
	;;
    pjsub | ssh)
	opt_dir=/home/opt/local/cores/intel
	compilervars_compile=". ${opt_dir}/compilers_and_libraries_2018.2.199/linux/bin/compilervars.sh intel64"
	;;
esac

#  compilervars for run-time
case $mpitype in
    intel)
	case $jobtype in
	    ssh)
		compilervars_runtime=$compilervars_compile
		;;
	    interactive | pjsub)
		compilervars_runtime=	
		;;
	esac
	;;
    mvapich)
	compilervars_runtime="export PATH=${mpi_dir}/bin:$PATH && export LD_LIBRARY_PATH=${mpi_dir}/lib:/opt/intel/compilers_and_libraries_2018.1.163/linux/compiler/lib/intel64_lin/:/opt/intel/compilers_and_libraries_2018.1.163/linux/mkl/lib/intel64_lin/:$LD_LIBRARY_PATH"
	;;
esac

case $mpitype in
    intel)
	case $jobtype in
	    interactive)
		i_mpi_hydra_bootstrap_exec=
		i_mpi_hydra_bootstrap=
		hosts=
		ssh=
		;;
	    pjsub)
		i_mpi_hydra_bootstrap_exec=
		i_mpi_hydra_bootstrap=
		hosts=
		ssh=
		;;
	    ssh)
		i_mpi_hydra_bootstrap_exec="export I_MPI_HYDRA_BOOTSTRAP_EXEC=/usr/bin/ssh"
		i_mpi_hydra_bootstrap="export I_MPI_HYDRA_BOOTSTRAP=ssh"
		hosts="-hosts $nodes"
		ssh="ssh -A c$LASTNODE"
		;;
	esac
	;;
    mvapich)
	case $jobtype in
	    interactive)
		hydra_bootstrap_exec=
		hydra_bootstrap=
		hosts=
		ssh=
		;;
	    pjsub)
		hydra_bootstrap_exec="export HYDRA_BOOTSTRAP_EXEC=/bin/pjrsh"
		hydra_bootstrap="export HYDRA_BOOTSTRAP=rsh"
		hosts=
		ssh=
		;;
	    ssh)
		hydra_bootstrap_exec="export HYDRA_BOOTSTRAP_EXEC=/usr/bin/ssh"
		hydra_bootstrap="export HYDRA_BOOTSTRAP=ssh"
		hosts="-hosts $nodes"
		ssh="ssh -A c$LASTNODE"
		;;
	esac
	;;
esac

if [ ${mck} -eq 1 ]; then
    makeopt="${makeopt} UTI_DIR=$uti_dir_mck"
    use_mck="#PJM -x MCK=$mck_dir"
    mck_mem="#PJM -x MCK_MEM=32G@0,8G@1"
    mcexec="${mck_dir}/bin/mcexec"
    nmcexecthr=$((omp_num_threads + 4))
    mcexecopt="-n $ppn --uti-use-last-cpu" # -t $nmcexecthr

    if [ ${use_hfi} -eq 1 ]; then
	mcexecopt="--enable-hfi1 $mcexecopt"
    fi

    if [ $disable_syscall_intercept -eq 0 ]; then
	mcexecopt="--enable-uti $mcexecopt"
    fi
else
    makeopt="${makeopt} UTI_DIR=$uti_dir_lin"
    use_mck=
    mck_mem=
    mcexec=
    mcexecopt=
fi

nalive=`PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes hostname | wc -l`
if [ $nalive -ne $nnodes ]; then
    echo "Error: One or more nodes are offline (#alive: $nalive)"
    exit
fi

if [ ${mck} -eq 0 ]; then
    offline=`PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes lscpu \| grep Off 2>&1 | dshbak -c | grep Off`
    if [ "$offline" != "" ]; then
	echo "Error: One or more CPUs are offline: $offline"
	exit
    fi
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
	PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
	    /usr/sbin/pidof $exe \| xargs -r sudo kill -9
    fi
fi

if [ ${reboot} -eq 1 ]; then
    if [ ${mck} -eq 1 ]; then
	if hostname  | grep ofp &>/dev/null; then

	    # -h: Hide idle thread to prevent KNL CPU from mux-ing resource and halving throughput 
	    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
	    sudo ${mck_dir}/sbin/mcreboot.sh -h -O -c 2-17,70-85,138-153,206-221,20-35,88-103,156-171,224-239,36-51,104-119,172-187,240-255,52-67,120-135,188-203,256-271 -r 2-5,70-73,138-141,206-209:0+6-9,74-77,142-145,210-213:1+10-13,78-81,146-149,214-217:68+14-17,82-85,150-153,218-221:69+20-23,88-91,156-159,224-227:136+24-27,92-95,160-163,228-231:137+28-31,96-99,164-167,232-235:204+32-35,100-103,168-171,236-239:205+36-39,104-107,172-175,240-243:18+40-43,108-111,176-179,244-247:19+44-47,112-115,180-183,248-251:86+48-51,116-119,184-187,252-255:87+52-55,120-123,188-191,256-259:154+56-59,124-127,192-195,260-263:155+60-63,128-131,196-199,264-267:222+64-67,132-135,200-203,268-271:223 -m 32G@0,12G@1

# perl -e 'for ($i=0;$i<68;$i++){if($i>0){print "+";}printf("%d,%d,%d:%d", $i+68,$i+136,$i+204,$i);}'

#	    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
#	    sudo ${mck_dir}/sbin/mcreboot.sh -O -c 68-271 -r 68,136,204:0+69,137,205:1+70,138,206:2+71,139,207:3+72,140,208:4+73,141,209:5+74,142,210:6+75,143,211:7+76,144,212:8+77,145,213:9+78,146,214:10+79,147,215:11+80,148,216:12+81,149,217:13+82,150,218:14+83,151,219:15+84,152,220:16+85,153,221:17+86,154,222:18+87,155,223:19+88,156,224:20+89,157,225:21+90,158,226:22+91,159,227:23+92,160,228:24+93,161,229:25+94,162,230:26+95,163,231:27+96,164,232:28+97,165,233:29+98,166,234:30+99,167,235:31+100,168,236:32+101,169,237:33+102,170,238:34+103,171,239:35+104,172,240:36+105,173,241:37+106,174,242:38+107,175,243:39+108,176,244:40+109,177,245:41+110,178,246:42+111,179,247:43+112,180,248:44+113,181,249:45+114,182,250:46+115,183,251:47+116,184,252:48+117,185,253:49+118,186,254:50+119,187,255:51+120,188,256:52+121,189,257:53+122,190,258:54+123,191,259:55+124,192,260:56+125,193,261:57+126,194,262:58+127,195,263:59+128,196,264:60+129,197,265:61+130,198,266:62+131,199,267:63+132,200,268:64+133,201,269:65+134,202,270:66+135,203,271:67 -m 32G@0,12G@1
	else
	    echo "unkwon host type"
	    exit 1
	fi
    else
	:
    fi
fi

case $mpitype in
intel)
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
export PSM2_RCVTHREAD=0

$uti_cpu_set
export I_MPI_PIN=$i_mpi_pin
$i_mpi_pin_processor_exclude_list
$i_mpi_pin_domain
$i_mpi_pin_order
$kmp_affinity

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
#export KMP_HW_SUBSET=64c,1t

export I_MPI_ASYNC_PROGRESS=off

#export I_MPI_STATS=native:20,ipm
#export I_MPI_STATS=ipm
#export I_MPI_DEBUG=4
#export I_MPI_HYDRA_DEBUG=on

ulimit -c unlimited 

$compilervars_runtime
$mpiexec -n $nprocs -ppn $ppn $hosts $ilpopt $enable_x $gdbcmd $mcexec $mcexecopt ${test_dir}/$exe -p $ppn -I $disable_syscall_intercept
#-l

EOF
) > ./job.sh
;;
mvapich)
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

$hydra_bootstrap_exec
$hydra_bootstrap

export HYDRA_PROXY_RETRY_COUNT=30

export OMP_NUM_THREADS=$omp_num_threads
# export OMP_STACKSIZE=64M
export KMP_BLOCKTIME=1

$mv2_cpu_mapping
$kmp_affinity

export MCKERNEL_RLIMIT_STACK=32M,16G
export KMP_STACKSIZE=64m
#export KMP_HW_SUBSET=64c,1t

export MPIR_CVAR_ASYNC_PROGRESS=0

$uti_cpu_set

ulimit -c unlimited 

$compilervars_runtime
$mpiexec -n $nprocs -ppn $ppn $hosts $enable_x $gdbcmd $mcexec $mcexecopt ${test_dir}/$exe -p $ppn -I $disable_syscall_intercept

EOF
) > ./job.sh
;;
esac

chmod u+x ./job.sh

if [ ${go} -eq 1 ]; then
    case $jobtype in 
	pjsub | ssh)
	    eval "$compilervars_compile"
	    ;&
	interactive)
	    rm -f ./$exe # To switch Linux and McKernel executables
	    make $makeopt ./$exe
	    ;;
    esac

    case $jobtype in 
	pjsub)
	    pjsub ./job.sh
	    ;;
	ssh | interactive)
	    PDSH_SSH_ARGS_APPEND="-tt -q" pdsh -t 2 -w $nodes \
		/usr/sbin/pidof $exe \| xargs -r sudo kill -9
	    $ssh ${test_dir}/job.sh
	    ;;
    esac
fi
