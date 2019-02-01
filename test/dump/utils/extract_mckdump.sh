#!/bin/sh
VMLINUX=/usr/lib/debug/lib/modules/3.10.0-693.1.1.el7.x86_64/vmlinux

if [ $# -lt 1 ]; then
	echo "Error: too few arguments"
	echo "usage: `basename $0` <vmcore> [outfile]"
	exit 1
fi

VMCORE=$1
OUTFILE=$2

echo "***** vmcore file info ******************************"
ls -lh ${VMCORE}

if [ "X${OUTFILE}" = "X" ]; then
	ext_opt=""
else
	ext_opt="-o ${OUTFILE}"
fi

if [ ! -f "${VMCORE}" ]; then
	echo "Error: vmcore (${VMCORE}) is not found" >&2
	exit 1
fi

echo "***** Extract mcdump from vmcore *******************"
/usr/bin/expect -c "
set timeout -1
spawn /usr/bin/crash $VMLINUX $VMCORE

expect \"crash>\"
send \"mod -s ihk_smp_x86 $MCMOD_DIR/kmod/ihk-smp-x86.ko\n\"

expect \"crash>\"
send \"extend $MCMOD_DIR/lib/ldump2mcdump.so\n\"

expect \"crash>\"
send \"ldump2mcdump 0 $ext_opt\n\"

expect \"crash>\"
send \"extend -u $MCMOD_DIR/lib/ldump2mcdump.so\n\"

expect \"crash>\"
send \"quit\n\"
"
echo ""
