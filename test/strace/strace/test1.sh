#!/bin/sh

if [ ! -f test1 ]; then
	gcc -o test1 test1.c
fi

rm -f check.log
$MCEXEC strace -o check.log ./test1

awk 'BEGIN{ng=0; ok=0; print "*** test1 start"}
/^gettid/{
	if ($0 ~/errno/) {
		print "test1-1 gettid NG"
		ng++
	}
	else {
		print "test1-1 gettid OK"
		ok++
	}
	test1=1
}
/^syscall_9999/{
	if ($0 ~/errno 38/) {
		print "test1-2 syscal_9999 OK"
		ok++
	}
	else {
		print "test1-2 syscall_9999 NG"
		ng++
	}
	test2=1
}
END {
	if (test1 != 1) {
		print "test1-1 gettid NG"
		ng++
	}
	if (test2 != 1) {
		print "test1-2 syscall_9999 NG"
		ng++
	}
	printf("*** test1 end ok=%d ng=%d\n", ok, ng)
	exit(ng)
}' check.log

rm -f check.log test1
