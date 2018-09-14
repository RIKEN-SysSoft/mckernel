#! /usr/bin/awk -f
BEGIN{
	ok = 0
	ng = 0
}

/^\(gdb\) b thr/{
	print "*** C771T001 gdb start OK"
	ok++
	st = 2
	next
}

/^\(gdb\) r/{
	st = 3
	next
}

/^\(gdb\) info threads/{
	st = 4
	next
}

/^\(gdb\) bt/{
	st = (bt == 0) ? 5 : 8
	bt++
	next
}

/^\(gdb\) n/{
	st = 6
	next
}

/^\(gdb\) thread 1/{
	st = 7
	next
}

/^\(gdb\) thread 2/{
	if (st != 0) {
		printf("*** C771T%03d backtrace command NG\n", st)
		ng++
	}
	st = 9
	next
}

/^\(gdb\) c/{
	st = 10
	next
}

/^\(gdb\) q/{
	st = 11
	next
}

/^\(gdb\)/             {
	printf("*** C771T%03d NG\n", st)
	ng++
	exit(1)
}

st == 2 {
	if ($0 ~/^Breakpoint 1 at/) {
		print "*** C771T002 breakpoint command OK"
		ok++
	}
	else {
		print "*** C771T002 breakpoint command NG"
		ng++
	}
	st = 0
}

st == 3 {
	if ($0 ~/^Starting program/) {
		print "*** C771T003 run command OK"
		ok++
	}
	else {
		print "*** C771T003 run command NG"
		ng++
	}
	st = 0
}

st == 4 {
	if ($0 ~/^  Id /) {
		print "*** C771T004 info threads command OK"
		ok++
	}
	else {
		print "*** C771T004 info threadsrun command NG"
		ng++
	}
	st = 0
}

st == 5 {
	if ($0 ~/^#0  thr/) {
		print "*** C771T005 backtrace command OK"
		ok++
	}
	else {
		print "*** C771T005 backtrace command NG"
		ng++
	}
	st = 0
}

st == 6 {
	if ($0 ~/^thread start tid=/) {
		print "*** C771T006 next command OK"
		ok++
	}
	else {
		print "*** C771T006 next command NG"
		ng++
	}
	st = 0
}

st == 7 {
	if ($0 ~/^\[Switching to thread 1/) {
		print "*** C771T007 thread command OK"
		ok++
	}
	else {
		print "*** C771T007 thread command NG"
		ng++
	}
	st = 0
}

st == 8 {
	if ($0 ~/ in main /) {
		print "*** C771T008 thread command OK"
		ok++
		st = 0
	}
}

st == 9 {
	if ($0 ~/^\[Switching to thread 2/) {
		print "*** C771T009 thread command OK"
		ok++
	}
	else {
		print "*** C771T009 thread command NG"
		ng++
	}
	st = 0
}

st == 10 {
	if ($0 ~/^Continuing/) {
		print "*** C771T010 continue command OK"
		ok++
	}
	else {
		print "*** C771T010 continue command NG"
		ng++
	}
	st = 0
}

END{
	if (st == 11) {
		print "*** C771T011 quit command OK"
		ok++
	}
	print "OK=" ok " NG=" ng
	exit(ng > 0 ? 1: 0)
}
