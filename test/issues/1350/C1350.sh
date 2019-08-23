#/bin/sh

USELTP=1
USEOSTEST=0

GDB_BUILD_DIR=/home/satoken/gdb_build/binutils-gdb-master/build

. ../../common.sh

base_dir=`pwd`
sed -i "s,@GDB@,${GDB_BUILD_DIR}/gdb/gdb,g" ./mcexec_gdb.sh
mcexec_gdb="${base_dir}/mcexec_gdb.sh"

issue=1350
tid=01

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
line=0

cd ${GDB_BUILD_DIR}
make check RUNTESTFLAGS="GDB=${mcexec_gdb} TRANSCRIPT=y gdb.base/gdb1555.exp" &> ${base_dir}/${tname}.txt
cd ${base_dir}

cat ${tname}.txt | awk '/gdb Summary/,/# of expected /'

line=`grep "# of expected passes\s*2" ./${tname}.txt | wc -l`

if [ ${line} -eq 1 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

for tp in rt_sigsuspend01 sigsuspend01 pause01 pause02 pause03
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep TPASS $tp.txt | wc -l`
	ng=`grep TFAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=%ng)"
	fi
	let tid++
	echo ""
done

