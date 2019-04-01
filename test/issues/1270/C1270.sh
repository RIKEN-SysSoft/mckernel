#!/usr/bin/bash

BOOTPARAM="-c 1-23,25-47 -m 16G -r 1-23:0+25-47:24 -O"

. ../../common.sh

for i in `seq 1 1000`; do
    echo "$i:"
    ./spawn_n.sh 46 ${MCK_DIR}/bin/mcexec -n 46 hostname
    sleep 0.05
done
