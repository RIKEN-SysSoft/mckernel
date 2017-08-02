#!/bin/sh
#source ./config
export MCKERNEL=${MCMOD_DIR}/smp-x86/kernel/mckernel.img
export INFILE=$1

if [ "X$INFILE" = X -o  "X$2" != X ]; then
	echo "usage: `basename $0` <mckdump>" >&2
	exit 1
fi

if [ ! -f "${INFILE}" ]; then
	echo "Error: mckdump is not found" >&2
	exit 1
fi

if [ ! -e "${MCKERNEL}" ]; then
	echo "Error: mckernel.img is not found"
	exit 1
fi

echo "***** dump_file info *************************"
ls -lh ${INFILE}

echo "***** Result of readelf -a ********************"
readelf -a ${INFILE}

echo ""
echo "***** Result of eclair ************************"
expect -c "
set timeout 20
spawn ${MCMOD_DIR}/bin/eclair -d $INFILE -k $MCKERNEL -l

expect \"(eclair)\"
send \"set pagination 0\n\"

expect \"(eclair)\"
send \"info threads\n\"

expect \"(eclair)\"
send \"info register\n\"

expect \"(eclair)\"
send \"bt\n\"

expect \"(eclair)\"
send \"quit\n\

"
echo "**********************************************"
exit 0
