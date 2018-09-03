#!/usr/bin/perl

while(<>) {
#    print $_;
    @row = split(/\s+/, $_);
#    print $row[0]."\n";
    $nsec{$row[0]} += $row[1];
    $count{$row[0]}++;
    if ($bitmap{$row[0]} == "") {
	push @names, ($row[0]);
    }
    $bitmap{$row[0]} = 1;
}

foreach $name (@names) {
    print $name . ',' . $nsec{$name} / $count{$name} . "\n";
}
