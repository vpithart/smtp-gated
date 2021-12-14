#
# check timeout for direct connection
#

use strict;
use vars qw(%set %conf %defs);

register(sub {
	$conf{'timeout_direct'} = 1;
	t_reload();

	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_one('STARTTLS', '220 OK');

	t_smtp_ehlo();
	t_expect_closed('cli', $conf{'timeout_direct'}+1);
	t_expect_closed('srv', $conf{'timeout_direct'}+1);

	t_debug_expect('CHILD_GONE');
});

# : vim: syntax=perl :
