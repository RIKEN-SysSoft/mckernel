#!/bin/bash

RED='\033[33m'
NC='\033[0m' # No Color

./sbin/ihkosctl 0 kmsg | awk '
	BEGIN{
		e = 0
		CMD = "addr2line -e smp-x86/kernel/mckernel.img  -fpia"
	}

	$0 == "[  0]: perf: printing buffer" {
		e=1
		next
	}

	$3 != "" && e == 1 {
		system(CMD " " $3)
		next
	}

	$3 == "" && e == 1 {
		print ""
		next
	}
' | awk '
     $1 == "(inlined" {
     	val = $3
     	$1 = $2 = $3 = ""
     	print "(inlinedby)         " "'$RED'"val"'$NC'" " " $0
     	next
     }
     $0 != "" {
     	first = $1
     	second = $2
     	$1 = ""
     	$2 = ""

     	print first " " "'$RED'"second"'$NC'" " " $0
	next
     }
     {
	print ""
     }
'
