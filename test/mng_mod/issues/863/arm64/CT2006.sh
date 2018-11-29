#!/bin/sh
## CT2006.sh COPYRIGHT FUJITSU LIMITED 2018 ##

MCEXEC=mcexec
sync
sudo /sbin/sysctl vm.drop_caches=3
$MCEXEC ./CT2006
