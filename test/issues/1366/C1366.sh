#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue=1366
tid=01

cp ${LTPBIN}/execve_* ./
cp ${LTPBIN}/execveat_* ./

for tp in execveat01 execveat02 execveat03 execve01 execve02 execve03 execve05
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo PATH=${LTPBIN}:${PATH} $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep PASS $tp.txt | wc -l`
	ng=`grep FAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=%ng)"
	fi
	let tid++
	echo ""
done

