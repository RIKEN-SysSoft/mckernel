#!/usr/bin/perl

while(<>) {
#    print $_;
    @row = split(/\s+/, $_);
#    print $row[0]."\n";
    $nsec{$row[0]} += $row[1];
    $count{$row[0]}++;
}

foreach $name (sort keys %nsec) {
    print $name . ',' . $nsec{$name} / $count{$name} . "\n";
}
