#!/bin/sh

count=`pgrep -c -f 'mcexec '`
if [ ${count} -gt 0 ]
then
	echo "kill process :" ${count}
	pgrep -l -f 'mcexec '
	pgrep -f 'mcexec ' | xargs kill -9
fi

