#
# check if locking works
# does not check real lock-duration
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_progress_init(6);
	$conf{'lock_duration'} = 60;
	$conf{'lock_on'} = 'never';

	# remove any previuos left locks
	#t_lock_remove();
	t_reload();

	# clean mail
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# infected mail, but don't lock
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_eicar_catch();

	# again, clean mail, shouldn't have been locked
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# infected mail, lock this time
	$conf{'lock_on'} = 'virus';
	t_reload();
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_eicar_catch();

	# reject mail, got locked
	t_progress_next();
	t_smtp_is_locked();

	# reject many
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
