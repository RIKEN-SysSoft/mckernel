#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0
MCREBOOT=0

. ../../../../common.sh

max_count=1000
groups=`groups | cut -d' ' -f 1`

## ISSUE01
result=0
for count in `seq -f %04g 1 ${max_count}`
do
	output=`MYGROUPS=${groups} ./ihklib001_lin -b 2>&1`
	echo "${output}" | grep -q "\[INFO\] All tests finished"
	if [ $? == 1 ]; then
		echo ""
		echo "${output}"
		echo "ISSUE01 not All tests finished."
		result=-1
		break
	fi

	echo "${output}" | grep -q "\[ NG \]"
	if [ $? == 0 ]; then
		echo ""
		echo "${output}"
		echo "ISSUE01 NG detected."
		result=-1
		break
	fi

	echo -en "ISSUE01 n=${count}/${max_count} ok.\r"
done
echo ""
if [ ${result} == 0 ]; then
	echo "ISSUE01: OK"
else
	echo "ISSUE01: NG"
fi

## ISSUE02
result=0
for count in `seq -f %04g 1 ${max_count}`
do
	output=`MYGROUPS=${groups} ./ihklib001_lin -x 2>&1`
	echo "${output}" | grep -q "\[INFO\] All tests finished"
	if [ $? == 1 ]; then
		echo ""
		echo "${output}"
		echo "ISSUE02 not All tests finished."
		result=-1
		break
	fi

	echo "${output}" | grep -q "\[ NG \]"
	if [ $? == 0 ]; then
		echo ""
		echo "${output}"
		echo "ISSUE02 NG detected."
		result=-1
		break
	fi

	echo -en "ISSUE02 n=${count}/${max_count} ok.\r"
done
echo ""
if [ ${result} == 0 ]; then
	echo "ISSUE02: OK"
else
	echo "ISSUE02: NG"
fi

sudo ./CT_001
sudo ./CT_002
sudo ./CT_003
sudo ./CT_004
sudo ./CT_005
sudo ./CT_006
sudo ./CT_007
sudo ./CT_008
