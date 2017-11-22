#!/bin/sh
#file_format_check.sh

filename="./input"

if [ "x$1" != "x" ]; then
	filename=$1
fi

cat /dev/null > outfile
cat ${filename} | while read line
do
    ./file_format_check.pl $line >> outfile
done
