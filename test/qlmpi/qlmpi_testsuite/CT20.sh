#!/bin/sh
PPOSDIR=/home/satoken/ppos
export PATH=$(PPOSDIR)/bin:$PATH
echo CT20001 device mapping program test START
echo CT20002 program 1 START
echo CT20003 check '"MPI_Send/Recv OK"'
ql_mpiexec_start -machinefile hostfile20 ./CT20a 1
echo CT20004 program 1 suspend
echo CT20005 program 2 START
echo CT20006 check '"MPI_Send/Recv OK"'
ql_mpiexec_start -machinefile hostfile20 ./CT20b 2
echo CT20007 program 2 suspend
echo CT20008 program 1 resume
echo CT20009 check '"MPI_Send/Recv OK"'
ql_mpiexec_start -machinefile hostfile20 ./CT20a 3
echo CT20010 program 1 suspend
echo CT20011 program 2 resume
echo CT20012 check '"MPI_Send/Recv OK"'
ql_mpiexec_start -machinefile hostfile20 ./CT20b 4
echo CT20013 program 2 suspend
echo CT20014 program 1 resume
ql_mpiexec_finalize -machinefile hostfile20 ./CT20a
echo CT20015 program 1 END
echo CT20016 program 2 resume
ql_mpiexec_finalize -machinefile hostfile20 ./CT20b
echo CT20017 program 2 END
echo CT20018 device mapping program test END
