#!/usr/bin/bash

(cd ~/project/os/mckernel/test/uti/mpi&&rm psm2-demo-server-epid-*;PSM2_RCVTHREAD=0 PMI_RANK=0  ~/project/os/install/bin/mcexec taskset -c 2 ./008 --ppn 1)&

(cd ~/project/os/mckernel/test/uti/mpi&&PSM2_RCVTHREAD=0 PMI_RANK=1 ~/project/os/install/bin/mcexec taskset -c 3 ./008 --ppn 1)


