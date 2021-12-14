#
# check timeout for SMTP session
#

use strict;
use vars qw(%set %conf %defs);

register(sub {
	#timeout_direct                 300
	#timeout_lookup                 10
	#timeout_scanner                30
	#timeout_spam                   30
	#timeout_session                20
	#timeout_idle                   300
	#timeout_connect                30

	t_progress_init(4);
	$conf{'timeout_idle'} = 1;
	t_reload();

	#
	# timeout_idle
	#
	t_progress_next();
	t_smtp_init();
	t_expect_closed('cli', $conf{'timeout_idle'}+1);
	t_expect_closed('srv', $conf{'timeout_idle'}+1);
	t_debug_expect('CHILD_GONE');

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_expect_closed('cli', $conf{'timeout_idle'}+1);
	t_expect_closed('srv', $conf{'timeout_idle'}+1);
	t_debug_expect('CHILD_GONE');

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_expect_closed('cli', $conf{'timeout_idle'}+1);
	t_expect_closed('srv', $conf{'timeout_idle'}+1);
	t_debug_expect('CHILD_GONE');

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_expect_closed('cli', $conf{'timeout_idle'}+1);
	t_expect_closed('srv', $conf{'timeout_idle'}+1);
	t_debug_expect('CHILD_GONE');
});

# : vim: syntax=perl :

