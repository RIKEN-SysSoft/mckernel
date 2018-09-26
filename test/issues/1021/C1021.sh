#!/bin/sh
USELTP=0
USEOSTEST=0

BOOTPARAM="-c 1-7,17-23,9-15,25-31 -m 10G@0,10G@1"
. ../../common.sh

if ! sudo ls /sys/kernel/debug | grep kmemleak > /dev/null 2>&1; then
	echo kmemleak: not found >&2
	exit 1
fi

################################################################################
sudo sh -c 'echo clear > /sys/kernel/debug/kmemleak'
$MCEXEC ./C1021
sudo $SBINDIR/mcstop+release.sh
sudo sh -c 'echo scan > /sys/kernel/debug/kmemleak'
if sudo cat /sys/kernel/debug/kmemleak | tee C1021T71.kmemleak | grep 'mcctrl'; then
	echo '*** C1021T61 NG (kmemleak)'
else
	echo '*** C1021T61 OK (kmemleak)'
fi
