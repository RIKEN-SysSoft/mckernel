#!/bin/sh

if [ "X$MCEXEC" = X ]; then
	echo FAIL: No mcexec found >&2
	exit 1
fi
$MCEXEC ./C1410T01 &
sleep 1

for i in `seq 1 5`
do
  echo "send SIGSTOP"
  kill -STOP `pidof mcexec`
  sleep 1
  echo "send SIGCONT"
  kill -CONT `pidof mcexec`
  sleep 1
done

echo "send SIGKILL"
kill -KILL `pidof mcexec`
