#!/bin/sh
LTPDIR=/home/shirasawa/ltp2015/testcases/bin
export PATH=/home/shirasawa/ltp2015/testcases/bin:$PATH
MCEXEC=/home/shirasawa/wallaby11-smp-x86/development/mic/mcexec
while read i;do
if $MCEXEC $LTPDIR/$i > $i.log; then
	echo $i: OK
else
	echo $i: NG
fi
done << EOF
clone01
clone03
clone04
clone06
clone07
fork01
fork02
fork03
fork04
fork07
fork08
fork09
fork10
fork11
execve01
execve02
execve03
wait02
wait401
wait402
waitid01
waitid02
waitpid01
waitpid02
waitpid03
waitpid04
waitpid05
waitpid07
waitpid08
waitpid09
waitpid12
waitpid13
ptrace01
ptrace02
ptrace05
EOF
