#!/usr/bin/env perl
use strict;
use warnings;

my %counts;
while (my $line = <STDIN>) {
    if ($line =~ /\[(\w+)\]/) {
        $counts{$1}++;
    }
}
for my $level (sort keys %counts) {
    printf "%-8s %d\n", $level, $counts{$level};
}
