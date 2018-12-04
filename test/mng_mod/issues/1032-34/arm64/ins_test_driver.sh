#!/bin/sh

MOD_NAME="test_driver"
DEV_PATH="/dev/test_rusage"

sudo insmod ./${MOD_NAME}.ko
sudo chmod 666 ${DEV_PATH}
