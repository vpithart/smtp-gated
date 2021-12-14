#
# check for valid ENHANCEDSTATUSCODES proxy-made responses
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	# no ENHANCEDSTATUSCODES
	t_reload();
	t_smtp_init();
	t_println('cli', 'EHLO fake.MUA');
	t_expect('srv', $prev);
	t_println_push('srv',
		'250-fake MTA greets fake.MUA',
		'250 PIPELINING'
	);
	t_expect_pop('cli');

	t_smtp_mail_rcpt();
	t_smtp_one('DATA', '354 go ahead');
	t_println_push('cli', t_eicar_body());
	t_expect_flush('srv');
	t_expect_closed('srv');

	t_expect_regex('cli', '^550 [a-zA-Z]');
	t_println('cli', 'HELO fake.MUA');
	t_expect_regex('cli', '^250 [a-zA-Z]');
	t_println('cli', 'EHLO fake.MUA');
	t_expect_regex('cli', '^250 [a-zA-Z]');
	t_println('cli', 'NOOP');
	t_expect_regex('cli', '^250 [a-zA-Z]');
	t_println('cli', 'MAIL FROM: <test@test.test>');
	t_expect_regex('cli', '^451 [a-zA-Z]');
	t_println('cli', 'RCPT TO: <test@test.test>');
	t_expect_regex('cli', '^503 [a-zA-Z]');
	t_println('cli', 'DATA');
	t_expect_regex('cli', '^503 [a-zA-Z]');
	t_println('cli', 'RSET');
	t_expect_regex('cli', '^250 [a-zA-Z]');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 [a-zA-Z]');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');


	# with ENHANCEDSTATUSCODES
	t_smtp_init();
	t_println('cli', 'EHLO fake.MUA');
	t_expect('srv', $prev);
	t_println_push('srv',
		'250-fake MTA greets fake.MUA',
		'250-ENHANCEDSTATUSCODES',
		'250 PIPELINING'
	);
	t_expect_pop('cli');

	t_smtp_mail_rcpt();
	t_smtp_one('DATA', '354 go ahead');
	t_println_push('cli', t_eicar_body());
	t_expect_flush('srv');
	t_expect_closed('srv');

	t_expect_regex('cli', '^550 5\.7\.1 ');
	t_println('cli', 'HELO fake.MUA');
	t_expect_regex('cli', '^250 2\.0\.0 ');
	t_println('cli', 'EHLO fake.MUA');
	t_expect_regex('cli', '^250 2\.0\.0 ');
	t_println('cli', 'NOOP');
	t_expect_regex('cli', '^250 2\.0\.0 ');
	t_println('cli', 'MAIL FROM: <test@test.test>');
	t_expect_regex('cli', '^451 4\.3\.2 ');
	t_println('cli', 'RCPT TO: <test@test.test>');
	t_expect_regex('cli', '^503 5\.5\.1 ');
	t_println('cli', 'DATA');
	t_expect_regex('cli', '^503 5\.5\.1 ');
	t_println('cli', 'RSET');
	t_expect_regex('cli', '^250 2\.0\.0 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 2\.0\.0 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');
});

# : vim: syntax=perl :
