#!/bin/sh

if [ ! -f test2 ]; then
	gcc -o test2 test2.c
fi

rm -f check.log
$MCEXEC strace  -e trace=process -f -o check.log ./test2

awk 'BEGIN{st=0;ng=0; ok=0; print "*** test2 start"}
/execve/{
	st++
	if ($0 ~/ = 0$/) {
		print "test2-" st " execve OK"
		ok++
	}
	else {
		print "test2-" st " execve NG"
		ng++
	}
}
/clone/{
	st++
	if ($0 ~/ = [1-9][0-9]*$/) {
		print "test2-" st " fork OK"
		ok++
	}
	else {
		print "test2-" st " fork NG"
		ng++
	}
}
/wait4/{
	st++
	if ($0 ~/ = [1-9][0-9]*$/) {
		print "test2-" st " wait OK"
		ok++
	}
	else {
		print "test2-" st " wait NG"
		ng++
	}
}
/SIGCHLD {/{
	st++
	print "test2-" st " SIGCHLD OK"
	ok++
	sigchld = 1
}
END {
	if (sigchld != 1) {
		st++
		print "test2-" st " SIGCHLD NG"
		ng++
	}
	printf("*** test2 end ok=%d ng=%d\n", ok, ng)
	exit(ng)
}' check.log

rm -f check.log test2
