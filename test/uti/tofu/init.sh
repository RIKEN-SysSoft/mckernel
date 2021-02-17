#!/usr/bin/bash

SCRIPT_PATH=$(readlink -m "${BASH_SOURCE[0]}")
TEST_HOME="${SCRIPT_PATH%/*/*/*}"

# stop TCS
sudo systemctl stop pxkrm-plugin-mckernel krm-iptables
sudo systemctl stop pxmonitor_pre.service pxmonitor_slaved.service pxnrd.service pxeventd.service pxpled.service paclmgr_notice.service pxkrm.service pxpwrd.service
sudo systemctl stop FJSVxosmck FJSVxoshpcpwr-plugin-mckernel pxpwrm_perm_mck.service
sudo rm -f /dev/shm/rml*

while true; do
    sudo systemctl status pxkrm-plugin-mckernel krm-iptables pxmonitor_slaved pxnrd pxpled paclmgr_notice pxkrm pxpwrd FJSVxosmck FJSVxoshpcpwr-plugin-mckernel pxpwrm_perm_mck | awk '/Active/ {print $2}' | grep -w active
    (( $? != 0 )) && break
done

# mcstop
if [[ "$1" == "mck" ]]; then
    MCREBOOT=0
    . $TEST_HOME/common.sh
fi

# cgroup
sudo bash -c 'echo "0,1,12-59" > /sys/fs/cgroup/cpuset/system.slice/cpuset.cpus'
sudo bash -c 'echo "0-7" > /sys/fs/cgroup/cpuset/system.slice/cpuset.mems'

if [ ! -e /sys/fs/cgroup/cpu/mckrt ]; then
        sudo mkdir /sys/fs/cgroup/cpu/mckrt
        sudo bash -c 'echo 950000 > /sys/fs/cgroup/cpu/mckrt/cpu.rt_runtime_us'
fi
grandma=$(ps  xao pid,ppid|awk '$1 == "'$PPID'" {print $2}')
sudo bash -c "echo $grandma > /sys/fs/cgroup/cpu/mckrt/tasks"

# tofu
sudo ./ctrl 1 1 1 0 0 0 1 1 1

if [[ "$1" == "mck" ]]; then
    mcreboot
fi
