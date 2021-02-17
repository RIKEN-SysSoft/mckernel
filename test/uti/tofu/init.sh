#!/usr/bin/bash

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
MCREBOOT=0
. ../../common.sh

sudo bash -c 'echo "0,1,12-59" > /sys/fs/cgroup/cpuset/system.slice/cpuset.cpus'
sudo bash -c 'echo "0-7" > /sys/fs/cgroup/cpuset/system.slice/cpuset.mems'

sudo ./ctrl 1 1 1 0 0 0 1 1 1

mcreboot
