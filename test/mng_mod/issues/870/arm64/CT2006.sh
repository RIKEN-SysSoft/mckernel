#!/bin/sh
## CT2006.sh COPYRIGHT FUJITSU LIMITED 2018 ##

sync
sudo /sbin/sysctl vm.drop_caches=3
./CT2000 ./CT2006
