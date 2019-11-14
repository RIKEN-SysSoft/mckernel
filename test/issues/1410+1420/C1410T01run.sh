#!/bin/sh
script -c 'sh ./C1410T01.sh' C1410T01.log
awk '
/send (SIGCONT|SIGKILL)/{
	if (st>0) {
		if (n > 5) {
			ok++
		}
		else{
			ng++
		}
	}
	st++
	n=0
	next
}
{n++}
END{
	if (ng > 0) {
		printf("*** C1410T01 FAIL ng=%d ok=%d\n", ng, ok)
		exit(1)
	}
	else {
		printf("*** C1410T01 PASS ng=%d ok=%d\n", ng, ok)
		exit(0)
	}
}' C1410T01.log
