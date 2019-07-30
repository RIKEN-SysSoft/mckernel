#!/usr/bin/perl

while(<>) {
    if(/\[\s+\d+\]\:\s([^+^ ]+)\+,/) {
	$addr = $1;
        $count{$addr}++;
	#print $addr . "\n";
    }
    if(/\[\s+\d+\]\:\s([^-^ ]+)\-,/) {
	$addr = $1;
        $count{$addr}--;
	#print $addr . "\n";
    }
}

foreach $key (sort keys(%count)) {
    if($count{$key} != 0) {
        print $key.",count=".$count{$key}."\n";
    }
}
