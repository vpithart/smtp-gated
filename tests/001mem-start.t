#
# Memleak checks
#

use strict;
use vars qw(%set %conf %defs $prev $pid_sp);

#VmSize:     2532 kB
#VmLck:         0 kB
#VmRSS:      1416 kB
#VmData:      308 kB
#VmStk:        24 kB
#VmExe:       488 kB
#VmLib:      1456 kB

register(sub {
	t_reload();

	open(MEM, "/proc/$pid_sp/status") || die "N/A: /proc pid status not supported\n";
	while (defined($_=<MEM>)) {
		chomp;
		next unless /^(Vm.*?):[ \t]+([0-9]+) .*$/;

		$set{"LEAK_$1"} = $2;
	}
	close(MEM);
});

# : vim: set syntax=perl :
