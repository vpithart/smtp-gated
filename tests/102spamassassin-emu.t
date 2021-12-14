#
# check if spam is blocked
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	# spam
	t_progress_init(3);

	$conf{'spam_max_size'} = 10000;
	$conf{'spam_threshold'} = 5;
	$conf{'lock_on'} = 'spam';
	t_reload();

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_gtube_catch();


	# spam, just log, don't block
	$conf{'spam_max_size'} = 10000;
	$conf{'lock_on'} = 'never';
	t_reload();
	t_lock_remove();

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_gtube_pass();
	t_smtp_quit();

	# spam, don't even scan
	$conf{'spam_max_size'} = 0;
	$conf{'lock_on'} = 'spam';
	t_reload();

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_gtube_pass();
	t_smtp_quit();
});

# : vim: syntax=perl :

