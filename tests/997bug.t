#
# check if script is called when virus found
#

use strict;
use vars qw(%set %conf %defs $prev $path);

register(sub {
	# make supervisor code happy
	t_reload();

	my $found = 0;

	open(F, $conf{'statefile'}) || die "can't open statefile: $!\n";
	while (defined($_=<F>)) {
		chomp;
		next unless m%Last BUG:%io;
		$found++;
		die "!BUG!\n" unless m%^Last BUG: +Thu Jan  1 01:00:00 1970$%o;
	}
	close(F);

	die "found $found 'Last BUG' status lines (should be exactly 1)!\n" unless $found == 1;
});

# : vim: syntax=perl :
