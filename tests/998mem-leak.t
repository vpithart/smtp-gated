#
# Memleak checks
#

use strict;
use vars qw(%set %conf %defs $prev $pid_sp);

register(sub {
	die "N/A: leak testing in effect\n" if $set{'leak'};

	t_reload();

	# 0kB/4kB?
	my $maxdiff = 384;

	#VmSize:     2532 kB
	#VmLck:         0 kB
	#VmRSS:      1416 kB
	#VmData:      308 kB
	#VmStk:        24 kB
	#VmExe:       488 kB
	#VmLib:      1456 kB

	my %mem;

	open(MEM, "/proc/$pid_sp/status") || die "N/A: /proc pid status not supported\n";
	while (defined($_=<MEM>)) {
		chomp;
		next unless /^(Vm.*?):[ \t]+([0-9]+) .*$/;

		$mem{$1} = $2;
	}
	close(MEM);

	my $diff = 0;
	printf STDERR "----------------------------\n";
	print STDERR " MEMORY UTILISATION SUMMARY\n";
	printf STDERR "----------------------------\n";
	printf STDERR "%-10s %8s %8s\n", 'type', 'before', 'after';
	printf STDERR "----------------------------\n";
	foreach (sort keys %mem) {
		printf STDERR "%-10s %8s %8s\n", $_, $set{"LEAK_$_"}, $mem{$_};
		$diff += $mem{$_} - $set{"LEAK_$_"};
	}
	printf STDERR "%-10s %8s %8s\n", "sum(diff)", "-->", $diff;
	printf STDERR "----------------------------\n";

	die "WARN: Memory usage threshold exceeded! Possible memory leak\n" if ($diff > $maxdiff);
});

# : vim: set syntax=perl :
