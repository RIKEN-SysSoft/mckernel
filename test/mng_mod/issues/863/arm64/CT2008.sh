#!/bin/sh
## CT2008.sh COPYRIGHT FUJITSU LIMITED 2018 ##

MCEXEC=mcexec
sync
sudo /sbin/sysctl vm.drop_caches=3
$MCEXEC ./CT2008
