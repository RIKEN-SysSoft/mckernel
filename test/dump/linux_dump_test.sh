#!/bin/sh

if [ $# -lt 2 ]; then
	echo "Error: too few arguments"
	echo "usage: `basename $0` <vmcore> <test_param_file>"
	exit 1
fi

# read test_param_file
source $2

VMCORE=$1

sudo sh -c "env MCMOD_DIR=${MCMOD_DIR} ./utils/extract_mckdump.sh ${VMCORE} ${OUTFILE}"
sleep 1

if [ "X${OUTFILE}" = "X" ]; then
	out_mckdump="./mcdump"
else
	out_mckdump="${OUTFILE}"
fi

if [ "X${ERROR_CASE}" = "X" ]; then
	# Normal case
	if [ ! -f ${out_mckdump} ]; then
		echo "Error: ${out_mckdump} is not created."
		exit 1
	fi

	# show dump_file info
	./utils/show_mckdump.sh ${out_mckdump}

else
	# Error case
	if [ -f ${out_mckdump} ]; then
		echo "Error: ${out_mckdump} is created."
		exit 1
	fi
fi

exit 0
