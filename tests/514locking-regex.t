#
# check if locking works for regex
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	die "N/A: regex not supported\n" if ($defs{'USE_REGEX'} || 'no') eq 'no';

	# spam
	t_progress_init(11);

	$conf{'regex_reject_helo'} = '^example.com$';
	$conf{'regex_enforce_helo'} = '.com$';
	$conf{'regex_reject_mail_from'} = '^sender@example.com$';
	$conf{'regex_enforce_mail_from'} = '^[^@]+@[^@]+$';
	$conf{'regex_reject_rcpt_to'} = '^recipient@example.com$';
	$conf{'regex_enforce_rcpt_to'} = '^[^@]+@[^@]+$';
	t_reload();

	# catch noting
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# regex_reject_helo
	t_progress_next();
	t_smtp_init();
	t_println('cli', 'HELO example.com');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# regex_enforce_helo
	t_progress_next();
	t_smtp_init();
	t_println('cli', 'HELO exampl3.net');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# EHLO: regex_reject_helo
	t_progress_next();
	t_smtp_init();
	t_println('cli', 'EHLO example.com');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# EHLO: regex_enforce_helo
	t_progress_next();
	t_smtp_init();
	t_println('cli', 'EHLO exampl3.net');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# regex_reject_mail_from
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_println('cli', 'MAIL FROM: <sender@example.com>');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# regex_enforce_mail_from
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_println('cli', 'MAIL FROM: <sender-example.com>');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# regex_reject_rcpt_to
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_println('cli', 'RCPT TO: <recipient@example.com>');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# regex_enforce_rcpt_to
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_println('cli', 'RCPT TO: <recipient-example.com>');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# catch noting, we should not have been locked
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();


	# skip_auth regex, moze do 015auth_skip.t?
	$conf{'auth_skip'} = 'regex';
	t_reload();

	t_progress_next();
	t_smtp_init();
	# helo would be catched anyway -- it's before authentication even takes place
	t_smtp_ehlo(auth => 1);
	t_println_push('cli',
		'MAIL FROM: <sender@example.com>',
		'RCPT TO: <recipient@example.com>',
		'RCPT TO: <recipient-example.com>',
	);
	t_expect_pop('srv');
	t_println_push('srv', '250 OK', '250 OK', '250 OK');
	t_expect_pop('cli');
	t_smtp_send();
	t_smtp_quit();


	# lock_on regex
	$conf{'auth_skip'} = 'none';
	$conf{'lock_on'} = 'regex';
	t_reload();
	die "TODO\n";
});

# : vim: syntax=perl :

