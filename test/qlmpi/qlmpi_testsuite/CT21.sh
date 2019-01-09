#!/bin/sh
export PPOSDIR=/home/satoken/ppos
export PATH=$PPOSDIR/bin:$PATH
echo CT21001 mcexec page table update test START
echo CT21002 program 1 START
echo CT21003 check '"data read OK"'
ql_mpiexec_start -machinefile hostfile21 -n 1 ./CT21a file1 1
echo CT21004 program 1 suspend
echo CT21005 program 2 START
echo CT21006 check '"data read OK"'
ql_mpiexec_start -machinefile hostfile21 -n 1 ./CT21b file1 1
echo CT21007 program 2 suspend
echo CT21008 program 1 resume
echo CT21009 check '"data read OK"'
ql_mpiexec_start -machinefile hostfile21 -n 1 ./CT21a file2 2
echo CT21010 program 1 suspend
echo CT21011 program 2 resume
echo CT21012 check '"data read OK"'
ql_mpiexec_start -machinefile hostfile21 -n 1 ./CT21b file2 2
echo CT21013 program 2 suspend
echo CT21014 program 1 resume
ql_mpiexec_finalize -machinefile hostfile21 -n 1 ./CT21a
echo CT21015 program 1 END
echo CT21016 program 2 resume
ql_mpiexec_finalize -machinefile hostfile21 -n 1 ./CT21b
echo CT21017 program 2 END
echo CT21018 mcexec page table update test END
