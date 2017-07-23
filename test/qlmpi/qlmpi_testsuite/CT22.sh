#!/bin/sh
PPOSDIR=/home/satoken/ppos
export PATH=$(PPOSDIR)/bin:$PATH
echo CT22001 OMP test START
echo CT22002 program 1 START
echo CT22003 check rank info
ql_mpiexec_start -genv OMP_NUM_THREADS 4 -machinefile hostfile22 ./CT22a
echo CT22004 program 1 suspend
echo CT22005 program 2 START
echo CT22006 check rank info
ql_mpiexec_start -genv OMP_NUM_THREADS 4 -machinefile hostfile22 ./CT22b
echo CT22007 program 2 suspend
echo CT22008 program 1 resume
echo CT22009 check rank info
ql_mpiexec_start -genv OMP_NUM_THREADS 4 -machinefile hostfile22 ./CT22a
echo CT22010 program 1 suspend
echo CT22011 program 2 resume
echo CT22012 check rank info
ql_mpiexec_start -genv OMP_NUM_THREADS 4 -machinefile hostfile22 ./CT22b
echo CT22013 program 2 suspend
echo CT22014 program 1 resume
ql_mpiexec_finalize -genv OMP_NUM_THREADS 4 -machinefile hostfile22 ./CT22a
echo CT22015 program 1 END
echo CT22016 program 2 resume
ql_mpiexec_finalize -genv OMP_NUM_THREADS 4 -machinefile hostfile22 ./CT22b
echo CT22017 program 2 END
echo CT22018 OMP test END
