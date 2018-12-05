#!/bin/sh

MOD_NAME="test_driver"

lsmod | grep ${MOD_NAME} &> /dev/null

if [ $? -eq 1 ]; then
	echo "Module test_driver is not currently loaded"
else
	sudo rmmod ${MOD_NAME}
fi

