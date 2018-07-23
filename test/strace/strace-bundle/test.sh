#!/bin/sh
export MCEXEC=../../../../mic/mcexec
echo '*** ptrace_setoptions start'
./ptrace_setoptions
if [ $? = 0 ]; then
	echo '*** ptrace_setoptions OK'
else
	echo '*** ptrace_setoptions NG'
fi
echo '*** qual_syscall start'
./qual_syscall
if [ $? = 0 ]; then
	echo '*** qual_syscall OK'
else
	echo '*** qual_syscall NG'
fi
echo '*** stat start'
./stat
if [ $? = 0 ]; then
	echo '*** stat OK'
else
	echo '*** stat NG'
fi
echo '*** strace-f start'
./strace-f
if [ $? = 0 ]; then
	echo '*** strace-f OK'
else
	echo '*** strace-f NG'
fi
