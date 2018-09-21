#!/bin/bash

. ../../common.sh

if "$MCEXEC" ./C1203T01; then
	echo "*** C1203T01: OK"
else
	echo "*** C1203T01: NG"
fi

# to run as user, chmod 1777 /dev/hugepages
if sudo HUGETLB_VERBOSE=2 HUGETLB_ELFMAP=RW HUGETLB_DEBUG=1 "$MCEXEC" ./C1203T02; then
	echo "*** C1203T02: OK"
else
	echo "*** C1203T02: NG"
fi
