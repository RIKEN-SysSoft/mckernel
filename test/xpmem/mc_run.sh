#!/usr/bin/env bash

test -e /tmp/xpmem.share && rm -f /tmp/xpmem.share
test -e /tmp/xpmem.lock && rm -f /tmp/xpmem.lock

# create TMP_SHARE_SIZE bytes defined in xpmem_test.h
for i in `seq 0 31` ; do
	echo -n 0 >> /tmp/xpmem.share
done
echo 0 > /tmp/xpmem.lock

# Run the main test app
mcexec $PWD/xpmem_master
exit 0

