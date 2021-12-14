#!/usr/bin/perl -w

use strict;

my $expr = '.';
my $fn = '/var/log/syslog';
my $quiet = 0;


while ($_=shift @ARGV) {
	if (/^-f/) {
		$fn = shift;
	} elsif (/^-q/) {
		$quiet = 1;
	} else {
		$expr = $_;
	}
}


if ($fn =~ /\.gz$/) {
	open(IN, "zcat $fn |") || die "can't open zcat $fn: $!\n";
} else {
	open(IN, $fn) || die "can't open $fn: $!\n";
}


my (%data, %locked);
while ($_=<IN>) {
	chomp;
	next unless m% (?:smtp-gated)\[([0-9]*)]: (.*)$%o;

	my ($msg, $pid) = ($_, $1);
	$_ = $2;

	if (m%^LOCK:LOCKED src=([^,]+), ident=(.*)$%o) {
		$locked{"$1:$2"}++;
		next;
	}

	if (m%^NEW %o) {
		if (defined($data{$pid})) {
			printf "# left: %s\n", $pid;
		}
		$data{$pid} = "";
	}

	$data{$pid} .= "$msg\n";

	if (m%^CLOSE(?: |:DIRECT |:TAKEN)%o) {
		printf "%s\n", $data{$pid} if $data{$pid} =~ $expr;
		delete $data{$pid};
	}
}
close(IN);

printf "# left:\n";
printf "LEFT %s:\n%s\n", $_, ($data{$_} || '-') foreach (sort keys %data);

printf "# locks:\n";
printf "LOCK:LOCKED [%s] %s time(s)\n", $_, $locked{$_} foreach (sort keys %locked);


