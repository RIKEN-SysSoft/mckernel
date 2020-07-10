#/bin/sh

USELTP=1
USEOSTEST=0

BOOTPARAM="-c 1-7 -m 10G@0,10G@1 -O"
. ../../common.sh

issue="1389"
tid=01

for tsuf in "01" "02.sh"
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	${MCEXEC} ./C1389T${tsuf}

	if [ $? -eq 0 ]; then
		echo "*** ${tname} PASSED ******************************"
	else
		echo "*** ${tname} FAILED ******************************"
	fi
	let tid++
	echo ""
done

for tp in "mtest01 -p80" "mtest01 -p80 -w" "mem01"
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
echo ${tp}
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee ${tname}.txt
	ok=`grep PASS ${tname}.txt | wc -l`
	ng=`grep FAIL ${tname}.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=$ng)"
	fi
	let tid++
	echo ""
done

