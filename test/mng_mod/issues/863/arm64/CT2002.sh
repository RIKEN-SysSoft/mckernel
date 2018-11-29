#!/bin/sh
## CT2002.sh COPYRIGHT FUJITSU LIMITED 2018 ##

MCEXEC=mcexec
sync
sudo /sbin/sysctl vm.drop_caches=3
$MCEXEC ./CT2002
