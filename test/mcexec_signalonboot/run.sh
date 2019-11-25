#!/bin/bash
# run.sh COPYRIGHT FUJITSU LIMITED 2019
test_dir=$(dirname "${BASH_SOURCE[0]}")

#
# init
#
. "${test_dir}/../common.sh"
SIGINT=2
SIGKILL=9
SIGTERM=15

"$BIN/mcexec" -c 0 -- ls 2>&1 | grep -q "signal_injection.patch is applied."
if [ $? -ne 0 ]; then
    echo "signal_injection.patch is not been applied." >&2
	exit 1
fi
sleep 1
meminfo="/sys/devices/virtual/mcos/mcos0/sys/devices/system/node/node0/meminfo"
exp_free_mem=`cat "$meminfo" | grep MemFree:`

#
# run
#
test_cases=`cat <<__EOF__
001 MCEXEC_UP_PREPARE_IMAGE:before $SIGINT
002 MCEXEC_UP_PREPARE_IMAGE:before $SIGKILL
003 MCEXEC_UP_PREPARE_IMAGE:before $SIGTERM
011 MCEXEC_UP_PREPARE_IMAGE:after $SIGINT
012 MCEXEC_UP_PREPARE_IMAGE:after $SIGKILL
013 MCEXEC_UP_PREPARE_IMAGE:after $SIGTERM
101 MCEXEC_UP_TRANSFER:before $SIGINT
102 MCEXEC_UP_TRANSFER:before $SIGKILL
103 MCEXEC_UP_TRANSFER:before $SIGTERM
111 MCEXEC_UP_TRANSFER:after $SIGINT
112 MCEXEC_UP_TRANSFER:after $SIGKILL
113 MCEXEC_UP_TRANSFER:after $SIGTERM
201 init_sigaction:before $SIGINT
202 init_sigaction:before $SIGKILL
203 init_sigaction:before $SIGTERM
211 init_sigaction:after $SIGINT
212 init_sigaction:after $SIGKILL
213 init_sigaction:after $SIGTERM
301 MCEXEC_UP_START_IMAGE:before $SIGINT
302 MCEXEC_UP_START_IMAGE:before $SIGKILL
303 MCEXEC_UP_START_IMAGE:before $SIGTERM
311 MCEXEC_UP_START_IMAGE:after $SIGINT
312 MCEXEC_UP_START_IMAGE:after $SIGKILL
313 MCEXEC_UP_START_IMAGE:after $SIGTERM
__EOF__`

IFS='
'
for tc in $test_cases
do
	no=`echo $tc | awk '{print $1}'`
	opt_i=`echo $tc | awk '{print $2}'`
	opt_s=`echo $tc | awk '{print $3}'`
	echo -n "$no: "
	bash -c "'$BIN/mcexec' -c 0 -- -i $opt_i -s $opt_s ls >/dev/null 2>&1" \
		>/dev/null 2>&1
	sleep 1

	free_mem=`cat "$meminfo" | grep MemFree:`
	if [ "$exp_free_mem" != "$free_mem" ]; then
		echo "NG - detected memory leak."
		echo "     before: ${exp_free_mem}"
		echo "     after: ${free_mem}"
		exp_free_mem=$free_mem
	else
		echo "OK"
	fi
done
exit 0
