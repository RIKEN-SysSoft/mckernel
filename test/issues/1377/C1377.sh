#!/bin/sh
USELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
if [ ! -f "$LTPBIN/dirtyc0w" ]; then
	echo BAD environment: LTP is too old >&2
	exit 1
fi

echo "*** C1377T01 start"
ng=0
ok=0
tp=dirtyc0w
for ((i=0; i<20; i++)); do
	for ((j=0; j<50; j++)); do
		sudo PATH=$PATH:$LTPBIN $MCEXEC $LTPBIN/$tp > $tp.txt 2>&1
		wok=`grep PASS $tp.txt | wc -l`
		wng=`grep FAIL $tp.txt | wc -l`
		if [ $wng != 0 ]; then
			echo -n '*'
			ng=`expr $ng + 1`
		elif [ $wok == 0 ]; then
			echo -n '?'
		else
			echo -n '.'
			ok=`expr $ok + 1`
		fi
	done
	echo
done

if [ $ng != 0 ]; then
	echo "*** C1377T01 FAILED ok: $ok, ng: $ng"
else
	echo "*** C1377T01 PASS ok: $ok"
fi



for i in wait02:02 wait401:03 waitpid01:04 waitpid02:05 waitpid04:06 \
	 waitpid05:07 waitpid06:08 waitpid07:09 waitpid08:10 waitpid09:11 \
	 waitpid10:12 waitpid11:13 waitpid12:14 waitpid13:15; do
	tp=`echo $i|sed 's/:.*//'`
	id=`echo $i|sed 's/.*://'`
	sudo PATH=$PATH:$LTPBIN $MCEXEC $LTPBIN/$tp 2>&1 | tee $tp.txt
	ok=`grep PASS $tp.txt | wc -l`
	ng=`grep FAIL $tp.txt | wc -l`
	if [ $ng = 0 ]; then
		echo "*** C1377T$id: $tp PASS ($ok)"
	else
		echo "*** C1377T$id: $tp FAIL (ok=$ok ng=$ng)"
	fi
done
