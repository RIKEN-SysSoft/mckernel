#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue="1512"
tid=01
arch=`uname -p`

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
tp="shmt09"
fail_flag=0
for rep in `seq 1 10`
do
	sudo $MCEXEC $LTPBIN/$tp 2>&1 > $tp.txt
	ok=`grep PASS $tp.txt | wc -l`
	ng=`grep FAIL $tp.txt | wc -l`
	echo "shmt09 rep $rep done. (ok=$ok ng=$ng)"
	if [ $ng -ne 0 ]; then
		if [ "${arch}" == "x86_64" ]; then
			echo "OK: Expected fail on ${arch}"
		else
			echo "NG: Unexpected fail on ${arch}"
			fail_flag=1
		fi
	else
		echo "OK: shmt09 PASS"
	fi
done
if [ ${fail_flag} -eq 0 ]; then
	echo "*** ${tname} PASSED"
else
	echo "*** ${tname} FAILED"
fi
echo ""
let tid++

while read tp
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	args=""
	if [ "$tp" == "mmapstress06" ]; then
		args="1"
	fi
	sudo $MCEXEC $LTPBIN/$tp $args 2>&1 | tee $tp.txt
	ok=`grep PASS $tp.txt | wc -l`
	ng=`grep FAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=$ng)"
	fi
	let tid++
	echo ""
done < ./ltp_list

