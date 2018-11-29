#!/bin/sh
## CT200x.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../../../common.sh

STRESSBIN=

${MCEXEC} ${STRESSBIN}/signalonread
if [ $? == 0 ]; then
	echo "CT1001-2: OK"
else
	echo "CT1001-2: NG"
fi

exist=`ls -l | grep testfile | grep -c $((2 * 1024 * 1024 * 1024))`
if [ ${exist} == 0 ]; then
	dd if=/dev/zero of=testfile bs=$((1024 * 1024)) count=$((2 * 1024))
	sync
fi

export PATH=$BIN:$PATH

./CT2001.sh
./CT2002.sh
./CT2003.sh
./CT2004.sh
./CT2005.sh
./CT2006.sh
./CT2007.sh
./CT2008.sh
