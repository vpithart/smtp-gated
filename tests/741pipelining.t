#
# test pipelining code... but how?!
#

use strict;
use vars qw(%set %conf %defs);

register(sub {
	my $max = $conf{'pipeline_size'} - 3;

	# pipeline_size = 32, test
	# pipeline_size = 64, test
	# pipeline_size = 128, test

	die "TODO\n";

});

# : vim: syntax=perl :

# pipeline - zobaczyc czy zostawi spoola po zerwaniu
# polaczenia, przy leave_on_error
__END__

for ($i=1; $i<$max; $i++) {
	$rcpt .= sprintf("RCPT TO: test%s@test.test\r\n", $i);
}

t_println('cli', $rcpt);
t_expect_regex('srv', ...);

for ($i=1; $i<$max; $i++) {
	$rcpt .= sprintf("250 OK\r\n");
}
t_println('srv');
t_expect_regex('cli', ...);

