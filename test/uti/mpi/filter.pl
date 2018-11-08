#!/usr/bin/perl

while(<>) { # For each line of hostfile 
    open();
    $found = 0;
    while(<>) {
        if($_ =~ /progress_fn,enter,tid=(\d+)/) {
            $tid = $1;
            $found = 1;
            #	print 'tid='.$tid."\n"
        }
        if($found == 1 && $_ =~ /^$tid/) {
            if($_ =~ /^$tid\s(\w+)/) {
                #	    print $1."\n";
                $freq{$1}{$hostname}++;
            }
        }
    }
}
foreach $key (sort(keys(%freq))) {
    print $key.",".$freq{$key}."\n";
}
