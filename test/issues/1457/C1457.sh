#!/bin/bash

. ${HOME}/.mck_test_config
export MCK_DIR
sudo ${MCK_DIR}/sbin/mcreboot.sh 1,3,5,7,9-12,50-58
${MCK_DIR}/bin/mcexec python C1457.py
sudo ${MCK_DIR}/sbin/mcstop+release.sh
