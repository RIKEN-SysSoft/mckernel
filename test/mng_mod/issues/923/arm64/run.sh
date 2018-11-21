#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0

. ../../../../common.sh

export PATH=${PATH}:${BIN}

./CT02
strace -f mcexec ls
