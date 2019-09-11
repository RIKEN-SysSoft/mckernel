#!/bin/bash
# run_error_injection.sh COPYRIGHT FUJITSU LIMITED 2019
test_dir=$(dirname "${BASH_SOURCE[0]}")

#
# read config
#
. "${test_dir}/../common.sh"

#
# init
#
echo "@@@ initialize:"
seed="$RANDOM"
RANDOM=$seed
echo "seed for \$RANDOM=$seed"

meminfo="/sys/devices/virtual/mcos/mcos0/sys/devices/system/node/node0/meminfo"
"${MCEXEC}" 0 ./signalonfork_wait -nt 1 -t $((1000*5)) >/dev/null
sleep 1
exp_free_mem=`cat "$meminfo" | grep MemFree:`
injection="/sys/devices/virtual/mcos/mcos0/sys/kernel/debug/signalonfork_test"

#
# run
#
while read label eq val
do
	if [ -z "$label" ]; then
		continue
	fi
	val=`echo "$val" | sed 's|,.*$||g'`

	msec=$((1000 + $RANDOM % 500))
	echo "$val" > "$injection"
	echo "@@@ run signalonfork_wait($label, $val) wait=$msec"
	"${MCEXEC}" 0 ./signalonfork_wait -nt 2 -t $msec > /dev/null
	sleep 1
	free_mem=`cat "$meminfo" | grep MemFree:`
	if [ "$exp_free_mem" != "$free_mem" ]; then
		echo "NG: detected memory leak."
		echo "before:"
		echo "  ${exp_free_mem}"
		echo "after:"
		echo "  ${free_mem}"
		exit -1
	fi
done <<__EOL__
	do_fork_release_cpuid_0                  = 0x010000,
	do_fork_destroy_thread_0                 = 0x010100,
	do_fork_destroy_thread_1                 = 0x010101,
	do_fork_destroy_thread_2                 = 0x010102,
	do_fork_release_ids_0                    = 0x010200,
	do_fork_release_ids_1                    = 0x010201,
	do_fork_free_mod_clone_arg_0             = 0x010300,
	do_fork_free_mod_clone_arg_1             = 0x010301,

	clone_thread_free_thread_0               = 0x020000,
	clone_thread_free_thread_1               = 0x020001,
	clone_thread_free_fp_regs_0              = 0x020100,
	clone_thread_free_fp_regs_1              = 0x020101,
	clone_thread_free_fork_process_proc_0    = 0x020200,
	clone_thread_free_fork_process_proc_1    = 0x020201,
	clone_thread_free_fork_process_asp_0     = 0x020300,
	clone_thread_free_fork_process_vm_0      = 0x020400,
	clone_thread_free_fork_process_cmdline_0 = 0x020500,
	clone_thread_free_fork_process_cmdline_1 = 0x020501,
	clone_thread_free_fork_process_mckfd_0   = 0x020600,
	clone_thread_free_fork_clone_process_0   = 0x020700,
	clone_thread_free_copy_user_ranges_0     = 0x020800,

	copy_user_ranges_err_rollback_0          = 0x030000,
__EOL__
echo "OK"
exit 0
