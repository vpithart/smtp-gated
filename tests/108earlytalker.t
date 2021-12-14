#
# earlytalker check
#

use strict;
use vars qw(%set %conf);

register(sub {
	t_reload();
	t_connect($cli);
	t_accept($srv);
	t_println('cli', 'HELO abrakadabra');
	t_expect_regex('cli', '^554 ');
	t_expect_closed($cli);
	t_expect_closed($srv);
	t_debug_expect('CHILD_GONE');
});

# : vim: syntax=perl :
