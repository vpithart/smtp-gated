#
# check timeout for fake session
#

use strict;
use vars qw(%set %conf %defs);

register(sub {
	t_progress_init(2);
	$conf{'timeout_session'} = 1;

	t_reload();

	#
	# instant timeout
	#
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_one('DATA', '354 go ahead');
	t_println_push('cli', t_eicar_body());
	t_expect_flush('srv');
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 [a-zA-Z]');

	t_expect_regex('cli', '^421 [a-zA-Z]');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	#
	# timeout after RSET
	#
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_one('DATA', '354 go ahead');
	t_println_push('cli', t_eicar_body());
	t_expect_flush('srv');
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 [a-zA-Z]');

	t_println('cli', 'RSET');
	t_expect_regex('cli', '^250 [a-zA-Z]');

	t_expect_regex('cli', '^421 [a-zA-Z]');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');
});

# : vim: syntax=perl :

