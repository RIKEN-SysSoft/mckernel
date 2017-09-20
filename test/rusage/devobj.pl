#!/usr/bin/perl

while(<>) {
    if(/\[\s+\d+\]\:\s([^+]+)\+,/) {
	$addr = $1;
        $countplus{$addr}++;
	#print $addr . "\n";
    }
    if(/\[\s+\d+\]\:\s([^-]+)\-,/) {
	$addr = $1;
        $countminus{$addr}--;
	#print $addr . "\n";
    }
    if(/devobj_get_page\([^)]+\):\s\S+\s(\S+)/) {
	$addr = $1;
        $devobj{$addr}++;
	#print $addr . "\n";
    }
}

foreach $key (sort keys(%devobj)) {
    if($countplus{$key} != 0 || $countminus{$key} != 0) {
        print $key.",count=".$countplus{$key}.",".$countminus{$key}."\n";
    }
}
