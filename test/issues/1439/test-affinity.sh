#!/bin/bash

. ${HOME}/.mck_test_config
export MCK_DIR
echo sudo ${MCK_DIR}/sbin/mcreboot.sh -m 1G@0,1G@1 -c 4-27,32-55 -O
sudo ${MCK_DIR}/sbin/mcreboot.sh -m 1G@0,1G@1 -c 4-27,32-55 -O
#sudo ${MCK_DIR}/sbin/mcreboot.sh -m 1G@0,1G@1 -c 4-27,32-55,60-83,88-111 -r 4-7,32-35:0+8-11,36-39:1+12-15,40-43:2+16-19,44-47:3+20-23,48-51:28+24-27,52-55:29+60-63,88-91:56+64-67,92-95:57+68-71,96-99:58+72-75,100-103:59+76-79,104-107:84+80-83,108-111:85 -O
echo ${MCK_DIR}/bin/mcexec python -u test-affinity.py
${MCK_DIR}/bin/mcexec python -u test-affinity.py
echo sudo ${MCK_DIR}/sbin/mcstop+release.sh
sudo ${MCK_DIR}/sbin/mcstop+release.sh


