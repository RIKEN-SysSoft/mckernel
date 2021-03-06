#!/bin/bash

# IHK SMP-x86 example boot script.
# author: Balazs Gerofi <bgerofi@riken.jp>
#      Copyright (C) 2014  RIKEN AICS
#
# This is an example script for loading IHK, configuring a partition and
# booting McKernel on it.  Unless specific CPUs and memory are requested,
# the script reserves half of the CPU cores and 512MB of RAM from
# NUMA node 0 when IHK is loaded for the first time.
# Otherwise, it destroys the current McKernel instance and reboots it using
# the same set of resources as it used previously.
# Note that the script does not output anything unless an error occurs.

prefix="/home/takagi/project/os/install"
BINDIR="${prefix}/bin"
SBINDIR="${prefix}/sbin"
ETCDIR=/home/takagi/project/os/install/etc
KMODDIR="${prefix}/kmod"
KERNDIR="${prefix}/smp-x86/kernel"
ENABLE_MCOVERLAYFS="yes"

mem="512M@0"
cpus=""
ikc_map=""

if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
	echo "You need at least bash-4.0 to run this script." >&2
	exit 1
fi

redirect_kmsg=0
mon_interval="-1"
DUMP_LEVEL=24
facility="LOG_LOCAL6"
chown_option=`logname 2> /dev/null`

if [ "`systemctl status irqbalance_mck.service 2> /dev/null |grep -E 'Active: active'`" != "" -o "`systemctl status irqbalance.service 2> /dev/null |grep -E 'Active: active'`" != "" ]; then
	irqbalance_used="yes"
else
	irqbalance_used="no"
fi

turbo=""
ihk_irq=""

while getopts :tk:c:m:o:f:r:q:i:d: OPT
do
	case ${OPT} in
	f)	facility=${OPTARG}
		;;
	o)	chown_option=${OPTARG}
		;;
	k)	redirect_kmsg=${OPTARG}
		;;
	c) cpus=${OPTARG}
		;;
	m) mem=${OPTARG}
		;;
	r) ikc_map=${OPTARG}
		;;
	q) ihk_irq=${OPTARG}
		;;
	t) turbo="turbo"
		;;
	d) DUMP_LEVEL=${OPTARG}
		;;
	i) mon_interval=${OPTARG}
		;;
	*)  echo "invalid option -${OPT}" >&2
		exit 1
	esac
done

# Start ihkmond
pid=`pidof ihkmond`
if [ "${pid}" != "" ]; then
    sudo kill -9 ${pid} > /dev/null 2> /dev/null
fi
if [ "${redirect_kmsg}" != "0" -o "${mon_interval}" != "-1" ]; then
    ${SBINDIR}/ihkmond -f ${facility} -k ${redirect_kmsg} -i ${mon_interval}
fi
#
# Revert any state that has been initialized before the error occured.
#
error_exit() {
	local status=$1

	case $status in
	mcos_sys_mounted)
		if [ "$enable_mcoverlay" == "yes" ]; then
			umount /tmp/mcos/mcos0_sys
		fi
		;&
	mcos_proc_mounted)
		if [ "$enable_mcoverlay" == "yes" ]; then
			umount /tmp/mcos/mcos0_proc
		fi
		;&
	mcoverlayfs_loaded)
		if [ "$enable_mcoverlay" == "yes" ]; then
			rmmod mcoverlay 2>/dev/null
		fi
		;&
	linux_proc_bind_mounted)
		if [ "$enable_mcoverlay" == "yes" ]; then
			umount /tmp/mcos/linux_proc
		fi
		;&
	tmp_mcos_mounted)
		if [ "$enable_mcoverlay" == "yes" ]; then
			umount /tmp/mcos
		fi
		;&
	tmp_mcos_created)
		if [ "$enable_mcoverlay" == "yes" ]; then
			rm -rf /tmp/mcos
		fi
		;&
	os_created)
		# Destroy all LWK instances
		if ls /dev/mcos* 1>/dev/null 2>&1; then
			for i in /dev/mcos*; do
				ind=`echo $i|cut -c10-`;
				if ! ${SBINDIR}/ihkconfig 0 destroy $ind; then
					echo "warning: failed to destroy LWK instance $ind" >&2
				fi
			done
		fi
		;&
	mcctrl_loaded)
		rmmod mcctrl 2>/dev/null || echo "warning: failed to remove mcctrl" >&2
		;&
	cpus_reserved)
		cpus=`${SBINDIR}/ihkconfig 0 query cpu`
		if [ "${cpus}" != "" ]; then
			if ! ${SBINDIR}/ihkconfig 0 release cpu $cpus > /dev/null; then
				echo "warning: failed to release CPUs" >&2
			fi
		fi
		;&
	mem_reserved)
		mem=`${SBINDIR}/ihkconfig 0 query mem`
		if [ "${mem}" != "" ]; then
			if ! ${SBINDIR}/ihkconfig 0 release mem $mem > /dev/null; then
				echo "warning: failed to release memory" >&2
			fi
		fi
		;&
	ihk_smp_loaded)
		rmmod ihk_smp_x86 2>/dev/null || echo "warning: failed to remove ihk_smp_x86" >&2
		;&
	ihk_loaded)
		rmmod ihk 2>/dev/null || echo "warning: failed to remove ihk" >&2
		;&
	irqbalance_stopped)
		if [ "`systemctl status irqbalance_mck.service 2> /dev/null |grep -E 'Active: active'`" != "" ]; then
			if ! systemctl stop irqbalance_mck.service 2>/dev/null; then
				echo "warning: failed to stop irqbalance_mck" >&2
			fi
			if ! systemctl disable irqbalance_mck.service >/dev/null 2>/dev/null; then
				echo "warning: failed to disable irqbalance_mck" >&2
			fi
			if ! etcdir=/home/takagi/project/os/install/etc perl -e '$etcdir=$ENV{'etcdir'}; @files = grep { -f } glob "$etcdir/proc/irq/*/smp_affinity"; foreach $file (@files) { $dest = substr($file, length($etcdir)); if(0) {print "cp $file $dest\n";} system("cp $file $dest 2>/dev/null"); }'; then
				echo "warning: failed to restore /proc/irq/*/smp_affinity" >&2
			fi
			if ! systemctl start irqbalance.service; then
				echo "warning: failed to start irqbalance" >&2;
			fi
		fi
		;&
	initial)
		# Nothing more to revert
		;;
	esac

	exit 1
}

ihk_ikc_irq_core=0

release=`uname -r`
major=`echo ${release} | sed -e 's/^\([0-9]*\).*/\1/'`
minor=`echo ${release} | sed -e 's/^[0-9]*.\([0-9]*\).*/\1/'`
patch=`echo ${release} | sed -e 's/^[0-9]*.[0-9]*.\([0-9]*\).*/\1/'`
linux_version_code=`expr \( ${major} \* 65536 \) + \( ${minor} \* 256 \) + ${patch}`
rhel_release=`echo ${release} | sed -e 's/^[0-9]*.[0-9]*.[0-9]*-\([0-9]*\).*/\1/'`
if [ "${release}" == "${rhel_release}" ]; then
	rhel_release="";
fi

enable_mcoverlay="no"

if [ "${ENABLE_MCOVERLAYFS}" == "yes" ]; then
	if [ "${rhel_release}" == "" ]; then
		if [ ${linux_version_code} -ge 262144 -a ${linux_version_code} -lt 262400 ]; then
			enable_mcoverlay="yes"
		fi
		if [ ${linux_version_code} -ge 263680 -a ${linux_version_code} -lt 263936 ]; then
			enable_mcoverlay="yes"
		fi
	else
		if [ ${linux_version_code} -eq 199168 -a ${rhel_release} -ge 327 ]; then
			enable_mcoverlay="yes"
		fi
		if [ ${linux_version_code} -ge 262144 -a ${linux_version_code} -lt 262400 ]; then
			enable_mcoverlay="yes"
		fi
	fi
fi

# Figure out CPUs if not requested by user
if [ "$cpus" == "" ]; then
	# Get the number of CPUs on NUMA node 0
	nr_cpus=`lscpu --parse | awk -F"," '{if ($4 == 0) print $4}' | wc -l`

	# Use the second half of the cores
	let nr_cpus="$nr_cpus / 2"
	cpus=`lscpu --parse | awk -F"," '{if ($4 == 0) print $1}' | tail -n $nr_cpus | xargs echo -n | sed 's/ /,/g'`
	if [ "$cpus" == "" ]; then
		echo "error: no available CPUs on NUMA node 0?" >&2
		exit 1
	fi
fi

# Remove mcoverlay if loaded
if [ "$enable_mcoverlay" == "yes" ]; then
	if grep mcoverlay /proc/modules &>/dev/null; then
		if [ "`cat /proc/mounts | grep /tmp/mcos/mcos0_sys`" != "" ]; then umount -l /tmp/mcos/mcos0_sys; fi
		if [ "`cat /proc/mounts | grep /tmp/mcos/mcos0_proc`" != "" ]; then umount -l /tmp/mcos/mcos0_proc; fi
		if [ "`cat /proc/mounts | grep /tmp/mcos/linux_proc`" != "" ]; then umount -l /tmp/mcos/linux_proc; fi
		if [ "`cat /proc/mounts | grep /tmp/mcos`" != "" ]; then umount -l /tmp/mcos; fi
		if [ -e /tmp/mcos ]; then rm -rf /tmp/mcos; fi
		if ! rmmod mcoverlay 2>/dev/null; then
			echo "error: removing mcoverlay" >&2
			exit 1
		fi
	fi
fi

# Stop irqbalance
if [ "${irqbalance_used}" == "yes" ]; then
    systemctl stop irqbalance_mck.service 2>/dev/null
    if ! systemctl stop irqbalance.service 2>/dev/null ; then
		echo "error: stopping irqbalance" >&2
		exit 1
    fi;

    if ! etcdir=/home/takagi/project/os/install/etc perl -e 'use File::Copy qw(copy); $etcdir=$ENV{'etcdir'}; @files = grep { -f } glob "/proc/irq/*/smp_affinity"; foreach $file (@files) { $rel = substr($file, 1); $dir=substr($rel, 0, length($rel)-length("/smp_affinity")); if(0) { print "cp $file $etcdir/$rel\n";} if(system("mkdir -p $etcdir/$dir")){ exit 1;} if(!copy($file,"$etcdir/$rel")){ exit 1;} }'; then
		echo "error: saving /proc/irq/*/smp_affinity" >&2
		error_exit "mcos_sys_mounted"
	fi;

# Prevent /proc/irq/*/smp_affinity from getting zero after offlining
# McKernel CPUs by using the following algorithm.
# if (smp_affinity & mck_cores) {
#     smp_affinity = (mck_cores ^ -1);
# }
    ncpus=`lscpu | grep -E '^CPU\(s\):' | awk '{print $2}'`
    smp_affinity_mask=`echo $cpus | ncpus=$ncpus perl -e 'while(<>){@tokens = split /,/;foreach $token (@tokens) {@nums = split /-/,$token; for($num = $nums[0]; $num <= $nums[$#nums]; $num++) {$ndx=int($num/32); $mask[$ndx] |= (1<<($num % 32))}}} $nint32s = int(($ENV{'ncpus'}+31)/32); for($j = $nint32s - 1; $j >= 0; $j--) { if($j != $nint32s - 1){print ",";} $nblks = ($j != $nint32s - 1) ? 8 : ($ENV{'ncpus'} % 32 != 0) ? int((($ENV{'ncpus'} + 3) % 32) / 4) : 8; for($i = $nblks - 1;$i >= 0;$i--){ printf("%01x",($mask[$j] >> ($i*4)) & 0xf);}}'`
#    echo cpus=$cpus ncpus=$ncpus smp_affinity_mask=$smp_affinity_mask

    if ! ncpus=$ncpus smp_affinity_mask=$smp_affinity_mask perl -e '@dirs = grep { -d } glob "/proc/irq/*"; foreach $dir (@dirs) { $hit = 0; $affinity_str = `cat $dir/smp_affinity`; chomp $affinity_str; @int32strs = split /,/, $affinity_str; @int32strs_mask=split /,/, $ENV{'smp_affinity_mask'}; for($i=0;$i <= $#int32strs_mask; $i++) { $int32strs_inv[$i] = sprintf("%08x",hex($int32strs_mask[$i])^0xffffffff); if($i == 0) { $len = int((($ENV{'ncpus'}%32)+3)/4); if($len != 0) { $int32strs_inv[$i] = substr($int32strs_inv[$i], -$len, $len); } } } $inv = join(",", @int32strs_inv); $nint32s = int(($ENV{'ncpus'}+31)/32); for($j = $nint32s - 1; $j >= 0; $j--) { if(hex($int32strs[$nint32s - 1 - $j]) & hex($int32strs_mask[$nint32s - 1 - $j])) { $hit = 1; }} if($hit == 1) { $cmd = "echo $inv > $dir/smp_affinity 2>/dev/null"; system $cmd;}}'; then
		echo "error: modifying /proc/irq/*/smp_affinity" >&2
		error_exit "mcos_sys_mounted"
	fi

fi

# Load IHK if not loaded
if ! grep -E 'ihk\s' /proc/modules &>/dev/null; then
	if ! taskset -c 0 insmod ${KMODDIR}/ihk.ko 2>/dev/null; then
		echo "error: loading ihk" >&2
		error_exit "irqbalance_stopped"
	fi
fi

# Increase swappiness so that we have better chance to allocate memory for IHK
echo 100 > /proc/sys/vm/swappiness

# Drop Linux caches to free memory
sync && echo 3 > /proc/sys/vm/drop_caches

# Merge free memory areas into large, physically contigous ones
echo 1 > /proc/sys/vm/compact_memory 2>/dev/null

sync

# Load IHK-SMP if not loaded and reserve CPUs and memory
if ! grep ihk_smp_x86 /proc/modules &>/dev/null; then
	if [ "$ihk_irq" == "" ]; then
		for i in `seq 64 255`; do
			if [ ! -d /proc/irq/$i ] && [ "`cat /proc/interrupts | grep ":" | awk '{print $1}' | grep -o '[0-9]*' | grep -e '^$i$'`" == "" ]; then
				ihk_irq=$i
				break
			fi
		done
		if [ "$ihk_irq" == "" ]; then
			echo "error: no IRQ available" >&2
			error_exit "ihk_loaded"
		fi
	fi
	if ! taskset -c 0 insmod ${KMODDIR}/ihk-smp-x86.ko ihk_start_irq=$ihk_irq ihk_ikc_irq_core=$ihk_ikc_irq_core 2>/dev/null; then
		echo "error: loading ihk-smp-x86" >&2
		error_exit "ihk_loaded"
	fi

	# Offline-reonline RAM (special case for OFP SNC-4 mode)
	if [ "`hostname | grep "c[0-9][0-9][0-9][0-9].ofp"`" != "" ] && [ "`cat /sys/devices/system/node/online`" == "0-7" ]; then
		for i in  0 1 2 3; do
			find /sys/devices/system/node/node$i/memory*/ -name "online" | while read f; do
				echo 0 > $f 2>&1 > /dev/null;
			done
			find /sys/devices/system/node/node$i/memory*/ -name "online" | while read f; do
				echo 1 > $f 2>&1 > /dev/null;
			done
		done
		for i in 4 5 6 7; do
			find /sys/devices/system/node/node$i/memory*/ -name "online" | while read f; do
				echo 0 > $f 2>&1 > /dev/null;
			done
			find /sys/devices/system/node/node$i/memory*/ -name "online" | while read f; do
				echo 1 > $f 2>&1 > /dev/null;
			done
		done
	fi

	if ! ${SBINDIR}/ihkconfig 0 reserve mem ${mem}; then
		echo "error: reserving memory" >&2
		error_exit "ihk_smp_loaded"
	fi
	if ! ${SBINDIR}/ihkconfig 0 reserve cpu ${cpus}; then
		echo "error: reserving CPUs" >&2;
		error_exit "mem_reserved"
	fi
fi

# Load mcctrl if not loaded
if ! grep mcctrl /proc/modules &>/dev/null; then
	if ! taskset -c 0 insmod ${KMODDIR}/mcctrl.ko 2>/dev/null; then
		echo "error: inserting mcctrl.ko" >&2
		error_exit "cpus_reserved"
	fi
fi

# Destroy all LWK instances
if ls /dev/mcos* 1>/dev/null 2>&1; then
	for i in /dev/mcos*; do
		ind=`echo $i|cut -c10-`;
		# Retry when conflicting with ihkmond 
		nretry=0
		until ${SBINDIR}/ihkconfig 0 destroy $ind || [ $nretry -lt 4 ]; do
		    sleep 0.25
		    nretry=$[ $nretry + 1 ]
		done
		if [ $nretry -eq 4 ]; then
		    echo "error: destroying LWK instance $ind failed" >&2
		    error_exit "mcctrl_loaded"
		fi
	done
fi

# Create OS instance
if ! ${SBINDIR}/ihkconfig 0 create; then
	echo "error: creating OS instance" >&2
	error_exit "mcctrl_loaded"
fi

# Assign CPUs
if ! ${SBINDIR}/ihkosctl 0 assign cpu ${cpus}; then
	echo "error: assign CPUs" >&2
	error_exit "os_created"
fi

if [ "$ikc_map" != "" ]; then
	# Specify IKC map
	if ! ${SBINDIR}/ihkosctl 0 set ikc_map ${ikc_map}; then
		echo "error: assign CPUs" >&2
		error_exit "os_created"
	fi
fi

# Assign memory
if ! ${SBINDIR}/ihkosctl 0 assign mem ${mem}; then
	echo "error: assign memory" >&2
	error_exit "os_created"
fi

# Load kernel image
if ! ${SBINDIR}/ihkosctl 0 load ${KERNDIR}/mckernel.img; then
	echo "error: loading kernel image: ${KERNDIR}/mckernel.img" >&2
	error_exit "os_created"
fi

# Set kernel arguments
if ! ${SBINDIR}/ihkosctl 0 kargs "hidos $turbo dump_level=${DUMP_LEVEL}"; then
	echo "error: setting kernel arguments" >&2
	error_exit "os_created"
fi

# Boot OS instance
if ! ${SBINDIR}/ihkosctl 0 boot; then
	echo "error: booting" >&2
	error_exit "os_created"
fi

# Set device file ownership
if ! chown ${chown_option} /dev/mcd* /dev/mcos*; then
	echo "warning: failed to chown device files" >&2
fi

# Overlay /proc, /sys with McKernel specific contents
if [ "$enable_mcoverlay" == "yes" ]; then
	if [ ! -e /tmp/mcos ]; then 
		mkdir -p /tmp/mcos; 
	fi
	if ! mount -t tmpfs tmpfs /tmp/mcos; then
		echo "error: mount /tmp/mcos" >&2
		error_exit "tmp_mcos_created"
	fi
	if [ ! -e /tmp/mcos/linux_proc ]; then 
		mkdir -p /tmp/mcos/linux_proc; 
	fi
	if ! mount --bind /proc /tmp/mcos/linux_proc; then
		echo "error: mount /tmp/mcos/linux_proc" >&2
		error_exit "tmp_mcos_mounted"
	fi
	if ! taskset -c 0 insmod ${KMODDIR}/mcoverlay.ko 2>/dev/null; then
		echo "error: inserting mcoverlay.ko" >&2
		error_exit "linux_proc_bind_mounted"
	fi
	while [ ! -e /proc/mcos0 ]
	do
		sleep 0.1
	done
	if [ ! -e /tmp/mcos/mcos0_proc ]; then 
		mkdir -p /tmp/mcos/mcos0_proc; 
	fi
	if [ ! -e /tmp/mcos/mcos0_proc_upper ]; then 
		mkdir -p /tmp/mcos/mcos0_proc_upper; 
	fi
	if [ ! -e /tmp/mcos/mcos0_proc_work ]; then 
		mkdir -p /tmp/mcos/mcos0_proc_work; 
	fi
	if ! mount -t mcoverlay mcoverlay -o lowerdir=/proc/mcos0:/proc,upperdir=/tmp/mcos/mcos0_proc_upper,workdir=/tmp/mcos/mcos0_proc_work,nocopyupw,nofscheck /tmp/mcos/mcos0_proc; then
		echo "error: mounting /tmp/mcos/mcos0_proc" >&2
		error_exit "mcoverlayfs_loaded"
	fi
	# TODO: How de we revert this in case of failure??
	mount --make-rprivate /proc

	while [ ! -e /sys/devices/virtual/mcos/mcos0/sys/setup_complete ]
	do
		sleep 0.1
	done
	if [ ! -e /tmp/mcos/mcos0_sys ]; then 
		mkdir -p /tmp/mcos/mcos0_sys; 
	fi
	if [ ! -e /tmp/mcos/mcos0_sys_upper ]; then 
		mkdir -p /tmp/mcos/mcos0_sys_upper; 
	fi
	if [ ! -e /tmp/mcos/mcos0_sys_work ]; then 
		mkdir -p /tmp/mcos/mcos0_sys_work; 
	fi
	if ! mount -t mcoverlay mcoverlay -o lowerdir=/sys/devices/virtual/mcos/mcos0/sys:/sys,upperdir=/tmp/mcos/mcos0_sys_upper,workdir=/tmp/mcos/mcos0_sys_work,nocopyupw,nofscheck /tmp/mcos/mcos0_sys; then
		echo "error: mount /tmp/mcos/mcos0_sys" >&2
		error_exit "mcos_proc_mounted"
	fi
	# TODO: How de we revert this in case of failure??
	mount --make-rprivate /sys

	touch /tmp/mcos/mcos0_proc/mckernel

	rm -rf /tmp/mcos/mcos0_sys/setup_complete

	# Hide NUMA related files which are outside the LWK partition
	for cpuid in `find /sys/devices/system/cpu/* -maxdepth 0 -name "cpu[0123456789]*" -printf "%f "`; do
		if [ ! -e "/sys/devices/virtual/mcos/mcos0/sys/devices/system/cpu/$cpuid" ]; then
			rm -rf /tmp/mcos/mcos0_sys/devices/system/cpu/$cpuid
			rm -rf /tmp/mcos/mcos0_sys/bus/cpu/devices/$cpuid
			rm -rf /tmp/mcos/mcos0_sys/bus/cpu/drivers/processor/$cpuid
		else
			for nodeid in `find /sys/devices/system/cpu/$cpuid/* -maxdepth 0 -name "node[0123456789]*" -printf "%f "`; do
				if [ ! -e "/sys/devices/virtual/mcos/mcos0/sys/devices/system/cpu/$cpuid/$nodeid" ]; then
					rm -f /tmp/mcos/mcos0_sys/devices/system/cpu/$cpuid/$nodeid
				fi
			done
		fi
	done
	for nodeid in `find /sys/devices/system/node/* -maxdepth 0 -name "node[0123456789]*" -printf "%f "`; do
		if [ ! -e "/sys/devices/virtual/mcos/mcos0/sys/devices/system/node/$nodeid" ]; then
			rm -rf /tmp/mcos/mcos0_sys/devices/system/node/$nodeid/*
			rm -rf /tmp/mcos/mcos0_sys/bus/node/devices/$nodeid
		else
			# Delete non-existent symlinks
			for cpuid in `find /sys/devices/system/node/$nodeid/* -maxdepth 0 -name "cpu[0123456789]*" -printf "%f "`; do
				if [ ! -e "/sys/devices/virtual/mcos/mcos0/sys/devices/system/node/$nodeid/$cpuid" ]; then
					rm -f /tmp/mcos/mcos0_sys/devices/system/node/$nodeid/$cpuid
				fi
			done

			rm -f /tmp/mcos/mcos0_sys/devices/system/node/$nodeid/memory*
		fi
	done
	rm -f /tmp/mcos/mcos0_sys/devices/system/node/has_*
	for cpuid in `find /sys/bus/cpu/devices/* -maxdepth 0 -name "cpu[0123456789]*" -printf "%f "`; do
		if [ ! -e "/sys/devices/virtual/mcos/mcos0/sys/bus/cpu/devices/$cpuid" ]; then
			rm -rf /tmp/mcos/mcos0_sys/bus/cpu/devices/$cpuid
		fi
	done
fi

# Start irqbalance with CPUs and IRQ for McKernel banned
if [ "${irqbalance_used}" == "yes" ]; then
    banirq=`cat /proc/interrupts| perl -e 'while(<>) { if(/^\s*(\d+).*IHK\-SMP\s*$/) {print $1;}}'`

    sed "s/%mask%/$smp_affinity_mask/g" $ETCDIR/irqbalance_mck.in | sed "s/%banirq%/$banirq/g" > /tmp/irqbalance_mck
	systemctl disable irqbalance_mck.service >/dev/null 2>/dev/null
	if ! systemctl link $ETCDIR/irqbalance_mck.service >/dev/null 2>/dev/null; then
		echo "error: linking irqbalance_mck" >&2
		error_exit "mcos_sys_mounted"
	fi

    if ! systemctl start irqbalance_mck.service 2>/dev/null ; then
		echo "error: starting irqbalance_mck" >&2
		error_exit "mcos_sys_mounted"
	fi
#    echo cpus=$cpus ncpus=$ncpus banirq=$banirq
fi
