#!/bin/sh

if [ $# -lt 4 ]; then
	echo "usage: $(basename $0) <base_val> <tgt_val> \
<lower_coef> <upper_coef>"
	exit 1
fi

base_val=$1
tgt_val=$2
l_coef=$3
u_coef=$4

lower=`echo "scale=1; ${base_val} * ${l_coef}" | bc`
upper=`echo "scale=1; ${base_val} * ${u_coef}" | bc`

if [ "$(echo "${tgt_val} > ${lower}" | bc)" -eq 1 -a \
	 "$(echo "${tgt_val} < ${upper}" | bc)" -eq 1 ] ||
	[ ${base_val} -eq ${tgt_val} ]; then
	echo " ${tgt_val} is IN ${lower} - ${upper} [OK]"
	exit 0
else
	echo " ${tgt_val} is OUT ${lower} - ${upper} [NG]"
	exit 1
fi
