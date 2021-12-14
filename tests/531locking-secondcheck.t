#
# check if second stage lock check works
#

use strict;
use vars qw(%conf);

register(sub {
	t_progress_init(6);
	$conf{'lock_duration'} = 600;
	$conf{'lock_on'} = 'virus';
	t_reload();

	# clean mail
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# start next connection ("background")
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();

	# now: infected session
	t_progress_next();
	t_change('cli-2', 'srv-2');
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_eicar_catch();

	# next new sessions should be rejected
	t_progress_next();
	t_smtp_is_locked();

	# back to old session, data should fail before ack
	t_progress_next();
	t_change();
	t_smtp_data();
	t_smtp_data_body();
	t_println_push('cli', '.');
	t_expect_closed('srv');
	t_expect_regex('cli', '^451 .*');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# new sessions should still be rejected
	t_progress_next();
	t_smtp_is_locked();

	# remove existing lock
	t_lock_remove();
});

# : vim: syntax=perl :
