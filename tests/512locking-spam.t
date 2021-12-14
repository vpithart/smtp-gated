#
# check if locking works
# does not check real lock-duration
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_progress_init(4);
	$conf{'lock_duration'} = 60;
	$conf{'spam_max_size'} = 10000;
	$conf{'spam_threshold'} = 5;
	$conf{'lock_on'} = 'spam';

	#t_lock_remove();
	t_reload();

	# 1. clean mail
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# 2. infected mail
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_gtube_catch();

	# 3. reject all
	t_progress_next();
	t_smtp_is_locked();

	# 4. reject many
	t_progress_next();
	t_connect('cli-1');
	t_connect('cli-2');
	t_connect('cli-3');
	t_expect_regex('cli-1', '^554 .*');
	t_expect_regex('cli-2', '^554 .*');
	t_expect_regex('cli-3', '^554 .*');
	t_expect_closed('cli-1');
	t_expect_closed('cli-2');
	t_expect_closed('cli-3');

	t_lock_remove();
});

# : vim: syntax=perl :
