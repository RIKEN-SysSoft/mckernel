#!/bin/sh
## run_issue1011.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../common.sh

result=-1

##########################
# Issue 1011 test(patch) #
##########################

output=`${MCEXEC} hostname 2>&1`
if [ $? != 0 ]; then
	echo "${output}" | grep -q "prepare: Invalid argument"
	if [ $? == 0 ]; then
		output=`tail -5 /var/log/messages`
		echo "${output}" | grep -q "kernel: mcexec_prepare_image: ERROR: # of sections: -1"
		if [ $? == 0 ]; then
			echo "Issue1011_0002: OK"
			result=0
		else
			echo "\"kernel: mcexec_prepare_image: ERROR: # of sections: -1\" not found."
		fi
	else
		echo "\"prepare: Invalid argument\" not found."
	fi
fi

if [ ${result} != 0 ]; then
	echo "Issue1011_0002: NG"
fi

exit ${result}
