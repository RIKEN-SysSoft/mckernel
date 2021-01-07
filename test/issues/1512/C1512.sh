#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue="1512"
tid=01

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
for rep in `seq 1 10`
do
	sudo $MCEXEC $LTPBIN/shmt09 &> /dev/null
	echo "shmt09 rep $rep done."
done
echo "*** ${tname} PASSED"

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

