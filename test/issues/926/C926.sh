#!/bin/sh
USELTP=0
USEOSTEST=0

BOOTPARAM="-c 1-7 -m 2G@0"
. ../../common.sh

$MCEXEC ./C926
