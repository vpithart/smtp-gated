#
# STARTTLS & direct proxy test
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_reload();

	# STARTTLS
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_one('STARTTLS', '220 OK');

	# this won't be av-checked, so should pass intact
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_eicar_pass();
	t_smtp_one('RSET', '250 OK');
	t_smtp_mail_rcpt();
	t_gtube_pass();
	t_smtp_quit();


	# STARTTLS rejected
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_one('STARTTLS', '454 TLS not available due to temporary reason');

	t_smtp_mail_rcpt();
	t_eicar_catch();


	# now STARTTLS forbidded by proxy configuration
	$conf{'forbid_starttls'} = 1;
	t_reload();

	t_smtp_init();
	t_smtp_ehlo();
	t_println('cli', 'STARTTLS');
	t_expect_regex('cli', '^502');
	t_smtp_mail_rcpt();
	t_eicar_catch();
});

# : vim: syntax=perl :
