#!/bin/sh

test_id=$1
log_file="./log/${test_id}.log"

num_addrs=`grep -c1 "large page request" $log_file`

for i in `seq 0 $((num_addrs - 1))`
do

    addr=`grep "large page request" $log_file | grep -e "trial#: $(printf "%03d" $i)" | grep -oE 'addr: \w{16}' | sed 's/addr: //'`
    pgsize_requested=`grep "large page request" $log_file | grep -e "trial#: $(printf "%03d" $i)" | grep -oE 'size: \w*' | sed 's/size: //'`
    pgsize_allocated=`grep "large page allocation" $log_file | grep -e $addr | grep -oE 'size: \w*' | sed 's/size: //'`

    if [ "$pgsize_requested" != "$pgsize_allocated" ]; then
	printf "\t[ NG ] "
    else
	printf "\t[ OK ] "
    fi

    printf "trial #: $(printf "%03d" $i), addr: $addr, requested size: $pgsize_requested, allocated size: $pgsize_allocated\n"

    if [ "$pgsize_requested" != "$pgsize_allocated" ]; then
	exit 1
    fi
done

exit 0
