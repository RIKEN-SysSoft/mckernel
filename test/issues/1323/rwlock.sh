#!/bin/sh
USELTP=0
USEOSTEST=0
BOOTPARAM="-c 2-7,9-15 -m 1G@0"

. ../../common.sh

################################################################################
$MCEXEC ./rwlock 1 10
$MCEXEC ./rwlock 2 10
$MCEXEC ./rwlock 3 10
$MCEXEC ./rwlock 4 10
