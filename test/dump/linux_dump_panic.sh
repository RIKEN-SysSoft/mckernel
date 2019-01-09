#!/bin/sh

if [ $# -lt 1 ]; then
        echo "Error: too few arguments."
        echo "usage: `basename $0` <param_file>"
fi

# read config
source ./config

# read testcase param
source $1

echo `grep "BELOW_CASES" $1` > ./done_panic

# mcexec processのkill
./utils/kill_mcexec.sh &> /dev/null

# stop mckernel
#echo "${MCMOD_DIR}/sbin/mcstop+release.sh"
sudo ${MCMOD_DIR}/sbin/mcstop+release.sh

# boot mckernel
#echo "${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT%,}"
sudo ${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT%,} ${DUMP_OPT}

sleep 1

if [ ! -e "/dev/mcos0" ]; then
	echo "Error: failed to mcreboot"
	exit 1
fi

# exec mckernel test program
for mc_proc in ${USR_PROC}
do
	echo "${MCMOD_DIR}/bin/mcexec ${mc_proc}"
	${MCMOD_DIR}/bin/mcexec ${mc_proc} &
done

# wait mmap
sleep 10

echo `grep "BELOW_CASES" $1` > ./done_panic
sleep 1

# do panic
sudo sh -c "echo 1 > /proc/sys/kernel/sysrq"
sudo sh -c "echo c > /proc/sysrq-trigger"

exit 0
