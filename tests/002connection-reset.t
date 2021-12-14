#
# test for connection reset by peer and others
# msg/ and lock/ should remain clean
#

use strict;
use vars qw(%set %conf %defs $prev);

# client close => proxy close
# server close => proxy close

register(sub {
	die "TODO\n";
});

# : vim: syntax=perl :
