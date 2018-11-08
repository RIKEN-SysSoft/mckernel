#!/bin/sh

USELTP=0
USEOSTEST=0

. ../../common.sh

sudo /bin/sh ${OSTESTDIR}/util/insmod_test_drv.sh

ulimit_c_bk=`ulimit -Sc`
# set ulimit -c unlimited to dump core
ulimit -Sc unlimited

$BINDIR/mcexec ./devmap_and_segv | tee ./maps.txt

# restore ulimit -c
ulimit -c ${ulimit_c_bk}

sudo /bin/sh ${OSTESTDIR}/util/rmmod_test_drv.sh

tid=001
echo "*** CT_$tid start *******************************"
echo "** check file type by readelf"
readelf -h ./core | grep -e "Type:.*CORE"
if [ $? == 0 ]; then
	echo "*** CT_$tid PASSED ******************************"
else
	echo "*** CT_$tid FAILED ******************************"
fi
echo ""

# check by gdb
VDSO_ADDR=`grep "\[vdso\]" ./maps.txt | cut -f 1 -d "-"`
DEVMAP_ADDR=`grep "mmap_dev2$" ./maps.txt | cut -f 1 -d "-"`
GDB_OUT="./gdb_out.txt"

expect -c "
	set timeout 3
	log_file -noappend ${GDB_OUT}

	spawn gdb --quiet -c ./core ./devmap_and_segv
	# check vdso addr
	expect \"(gdb)\"
	send \"x 0x${VDSO_ADDR}\n\"

	#check devmap addr
	expect \"(gdb)\"
	send \"x 0x${DEVMAP_ADDR}\n\"

	#check backtrace
	expect \"(gdb)\"
	send \"bt\n\"

	#check info registers
	expect \"(gdb)\"
	send \"info registers\n\"

	# quit gdb_test
	expect \"(gdb)\"
	send \"quit\n\"

	log_file
	interact
" > /dev/null

tid=002
echo "*** CT_$tid start *******************************"
echo "** check that core contains vdso data"
grep -A 1 "(gdb) x 0x${VDSO_ADDR}" ${GDB_OUT}
grep -A 1 "(gdb) x 0x${VDSO_ADDR}" ${GDB_OUT} | tail -1 | grep -q "0x${VDSO_ADDR}:\s*0x[0-9a-f]\+"
if [ $? == 0 ]; then
	echo "*** CT_$tid PASSED ******************************"
else
	echo "*** CT_$tid FAILED ******************************"
fi
echo ""

tid=003
echo "*** CT_$tid start *******************************"
echo "** check that core dose NOT contain devmap data"
grep -A 1 "(gdb) x 0x${DEVMAP_ADDR}" ${GDB_OUT}
grep -A 1 "(gdb) x 0x${DEVMAP_ADDR}" ${GDB_OUT} | tail -1 | grep -q "0x${VDSO_ADDR}:\s*0x[0-9a-f]\+"
if [ $? == 1 ]; then
	echo "*** CT_$tid PASSED ******************************"
else
	echo "*** CT_$tid FAILED ******************************"
fi
echo ""

tid=004
echo "*** CT_$tid start *******************************"
echo "** check that core can be backtraced"
grep -A 1 "(gdb) bt" ${GDB_OUT}
grep -A 1 "(gdb) bt" ${GDB_OUT} | tail -1 | grep -q "^#0.*in main"
if [ $? == 0 ]; then
	echo "*** CT_$tid PASSED ******************************"
else
	echo "*** CT_$tid FAILED ******************************"
fi
echo ""

tid=005
echo "*** CT_$tid start *******************************"
echo "** check that core can be got info registers"
grep -A 30 "(gdb) info registers" ${GDB_OUT}
grep -A 30 "(gdb) info registers" ${GDB_OUT} | grep -q "^rip\s*0x.*main"
if [ $? == 0 ]; then
	echo "*** CT_$tid PASSED ******************************"
else
	echo "*** CT_$tid FAILED ******************************"
fi
echo ""
