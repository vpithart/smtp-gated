#
# check for multi rcpt transaction
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	my ($max, @mails, $i);


	$conf{'log_helo'} = 1;
	$conf{'log_mail_from'} = 0x03;
	$conf{'log_rcpt_to'} = 0x03;
	t_reload();

	$max = $conf{'pipeline_size'} - 2;

	t_smtp_init();
	t_smtp_ehlo();

	push @mails, 'MAIL FROM: <user@test.test>';
	# do not exceed pipeline queue size
	for ($i=0; $i<$max; $i++) {
		 push @mails, sprintf('RCPT TO: <user%s@test%s.test>', $i, $i);
	}

	t_println_push('cli', @mails);
	t_expect_pop('srv');

	@mails = map { '250 OK' } @mails;
	t_println_push('srv', @mails);
	t_expect_pop('cli');

	t_smtp_one('DATA', '354 go ahead');

	t_println_push('cli',
		'From: source@test.com',
		'To: source@test.com',
		'',
		'the one and only line',
		'.'
	);

	t_expect_pop('srv');

	t_println('srv', '250 Spool OK');
	t_expect('cli', $prev);

	t_smtp_quit();
});

# : vim: syntax=perl :

