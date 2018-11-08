#!/bin/sh
USELTP=1
USEOSTEST=1
GDBBUILDDIR="$HOME/rpmbuild/BUILD/gdb-7.6.1/build-x86_64-redhat-linux-gnu"

. ../../common.sh

#===============================================================================
expect -c "
set timeout 60
spawn "$MCEXEC" gdb ./C771T001
expect \"(gdb)\"
send -- \"b thr\n\"

expect \"(gdb)\"
send -- \"r\n\"

expect \"(gdb)\"
send -- \"info threads\n\"

expect \"(gdb)\"
send -- \"bt\n\"

expect \"(gdb)\"
send -- \"n\n\"

expect \"(gdb)\"
send -- \"thread 1\n\"

expect \"(gdb)\"
send -- \"bt\n\"

expect \"(gdb)\"
send -- \"thread 2\n\"

expect \"(gdb)\"
send -- \"c\n\"

expect \"(gdb)\"
send -- \"q\n\"

expect eof
" | tee C771T001.txt

echo checking result...
awk -f C771T001.awk C771T001.txt
rm -f C771T001.txt

sleep 5
"$SBIN"/ihkosctl 0 clear_kmsg
"$SBIN"/ihkosctl 0 ioctl 40000000 1
"$SBIN"/ihkosctl 0 ioctl 40000000 2
"$SBIN"/ihkosctl 0 kmsg | tee C771T012.txt
if grep ' 0 processes are found' C771T012.txt > /dev/null 2>&1 && \
   grep ' 0 threads are found' C771T012.txt > /dev/null 2>&1; then
	echo "*** C771T012 no processes and threads found OK"
else
	echo "*** C771T012 processes and threads are exists NG"
fi
rm -f C771T012.txt

#===============================================================================
if [ -x "$GDBBUILDDIR/gdb/testsuite/gdb.threads/bp_in_thread" ] ;then
	if [ -d gdb-result ]; then
		rm -rf gdb-result
	fi
	mkdir -p gdb-result/raw/linux gdb-result/raw/mck
	mkdir -p gdb-result/linux gdb-result/mck
	export gdb_builddir="$GDBBUILDDIR"
	export MCEXEC

	id=13
	while read line; do
		cat=`echo $line | awk '{print $1}'`
		exp=`echo $line | awk '{print $2}'`
		./gdb_test.sh $cat $exp 2>&1 | tee $cat-$exp.txt
		if grep "【PASS】" $cat-$exp.txt > /dev/null 2>&1; then
			echo "*** C771T0$id: $cat-$exp OK"
		else
			echo "*** C771T0$id: $cat-$exp NG"
		fi
		rm -f $cat-$exp.txt
		id=`expr $id + 1`
	done < gdblist
else
	echo '***' No GDB build dir. skip GDB tests >&2
fi

#===============================================================================
$MCEXEC ./C771T033

#===============================================================================
$MCEXEC "$TESTMCK" -s ptrace -n 19 | tee C771T036.txt
if grep "RESULT: ok" C771T036.txt > /dev/null 2>&1; then
	echo "*** C771T036: ostest-ptrace-19 OK"
else
	echo "*** C771T036: ostest-ptrace-19 NG"
fi
rm -f C771T036.txt

#===============================================================================
$MCEXEC ./C771T037

#===============================================================================
id=43
while read tp; do
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C771T0$id: $tp OK ($ok)"
	else
		echo "*** C771T0$id: $tp NG (ok=$ok ng=$ng)"
	fi
	rm -f $tp.txt
	id=`expr $id + 1`
done < ltplist
