#
# check is SMTP verbs are case-insensitive
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_reload();
	t_smtp_init();
	t_smtp_ehlo();

	t_println_push('cli',
		'MaIl fRoM: <user@test.test>',
		'rCpT To: <user@test.test>'
	);
	t_expect_pop('srv');
	t_println_push('srv', '250 OK', '250 OK');
	t_expect_pop('cli');

	t_smtp_one('DatA', '354 go ahead');
	t_println_push('cli', t_eicar_body());

	t_expect_flush('srv');
	t_expect_closed('srv');

	# no enhancedstatuscodes!
	t_expect_regex('cli', '^550 [a-zA-Z]');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');
});

# : vim: syntax=perl :
