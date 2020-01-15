#/bin/sh

USELTP=1
USEOSTEST=0

. ../../common.sh

issue="1458"
tid=01

arch=`uname -p`
if [ "$arch" == "x86_64" ]; then
	PS_LIST="12 21 30"
elif [ "$arch" == "aarch64" ]; then
	PS_LIST="16 21 29"
fi

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ng=0
for mapps in ${PS_LIST}
do
	for unmapps in ${PS_LIST}
	do
		if [ $unmapps -ge $mapps ]; then
			continue
		fi
		echo "** Map pgshift:${mapps} Unmap pgshift:${unmapps}"
		sudo ${MCEXEC} ./C1458T01 ${mapps} ${unmapps}
		if [ $? -ne 0 ]; then
			$((++ng))
		fi
	done
done
if [ $ng -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ng=0
for mapps in ${PS_LIST}
do
	for unmapps in ${PS_LIST}
	do
		if [ $unmapps -ge $mapps ]; then
			continue
		fi
		echo "** Map pgshift:${mapps} Unmap pgshift:${unmapps}"
		sudo ${MCEXEC} ./C1458T02 ${mapps} ${unmapps}
		if [ $? -ne 0 ]; then
			$((++ng))
		fi
	done
done
if [ $ng -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

tname=`printf "C${issue}T%02d" ${tid}`
echo "*** ${tname} start *******************************"
ng=0
for mapps in ${PS_LIST}
do
	for unmapps in ${PS_LIST}
	do
		if [ $unmapps -ge $mapps ]; then
			continue
		fi
		echo "** Map pgshift:${mapps} Unmap pgshift:${unmapps}"
		sudo ${MCEXEC} ./C1458T02 ${mapps} ${unmapps}
		if [ $? -ne 0 ]; then
			$((++ng))
		fi
	done
done
if [ $ng -eq 0 ]; then
	echo "*** ${tname} PASSED ******************************"
else
	echo "*** ${tname} FAILED ******************************"
fi
let tid++
echo ""

for tp in shmat01 shmat02 shmat03 shmctl01 shmctl02 shmctl03 shmctl04 shmdt01 shmdt02 shmget01 shmget02 shmget03 shmget04 shmget05
do
	tname=`printf "C${issue}T%02d" ${tid}`
	echo "*** ${tname} start *******************************"
	sudo $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep PASS $tp.txt | wc -l`
	ng=`grep FAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** ${tname} PASSED ($ok)"
	else
		echo "*** ${tname} FAILED (ok=$ok ng=$ng)"
	fi
	let tid++
	echo ""
done
