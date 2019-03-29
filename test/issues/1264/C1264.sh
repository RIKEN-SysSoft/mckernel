#!/usr/bin/bash

BOOTPARAM="-c 1-15 -m 16G -O"

. ../../common.sh

for i in `seq 1 400`; do
    echo "$i:"
    ./spawn_n.sh 14 ${MCK_DIR}/bin/mcexec -n 14 hostname
    sleep 0.05
done
