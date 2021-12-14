#
# check if locking expiration works
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_progress_init(5);
	$conf{'lock_duration'} = 600;
	$conf{'lock_on'} = 'virus';

	# remove possibly left lock
	t_reload();

	# clean mail
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# infected mail
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_eicar_catch();

	# reject
	t_progress_next();
	t_smtp_is_locked();

	# reject after dummy reload
	t_progress_next();
	t_reload();
	t_smtp_is_locked();

	# lock "expires"
	t_progress_next();
	$conf{'lock_duration'} = 1;
	t_reload();
	sleep(1);

	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# remove existing lock
	#t_lock_remove();
});

# : vim: syntax=perl :
