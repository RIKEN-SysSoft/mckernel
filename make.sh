#!/bin/sh
ihkdir=`pwd`/../ihk
installdir=
kerneldir=
target=
cleanflag=
while [ "X$1" != X ]; do
	case "$1" in
	    clean)
		cleanflag=1
		;;
	    installdir=*)
		installdir="`echo $1 | sed 's/^installdir=//'`"
		;;
	    ihkdir=*)
		ihkdir="`echo $1 | sed 's/^ihkdir=//'`"
		;;
	    kerneldir=*)
		kerneldir="`echo $1 | sed 's/^kerneldir=//'`"
		;;
	    target=*)
		target="`echo $1 | sed 's/^target=//'`"
		;;
	    *)
		echo "unknown option $1" >&2
		exit 1
		;;
	esac
	shift
done

if [ "X$cleanflag" != X ]; then
	(cd executer/kernel; make clean)
	(cd executer/user; make clean)
	rm -rf kernel/build
	exit 0
fi

if [ "X$target" = X ]; then
	if [ -f $ihkdir/target ]; then
		target="`cat $ihkdir/target`"
	fi
fi
if [ "X$target" = X ]; then
	target=attached-mic
fi

if [ "X$installdir" != X ]; then
	mkdir -p "$installdir"
fi
(cd executer/kernel; make)
if [ -f executer/kernel/mcctrl.ko ]; then
	if [ "X$installdir" != X ]; then
		cp executer/kernel/mcctrl.ko "$installdir"
	fi
else
	echo "executer/kernel/mcctrl.ko could not be built" >&2
	exit 1
fi

for tgt in $target; do
	case "$tgt" in
	    attached-mic)
		(cd kernel; mkdir -p build; make O=`pwd`/build)
		krn=kernel/build/$tgt/kernel.img
		;;
	    *)
		echo "unknown target $tgt" >&2
		exit 1
		;;
	esac
	if [ -f $krn ]; then
		if [ "X$installdir" != X ]; then
			cp $krn "$installdir"
		fi
	else
		echo "$krn could not be built" >&2
		exit 1
	fi
done

(cd executer/user; make)
if [ -f executer/user/mcexec ]; then
	if [ "X$installdir" != X ]; then
		cp executer/user/mcexec "$installdir"
	fi
else
	echo "executer/user/mcexec could not be built" >&2
	exit 1
fi
