#
# check presense validity of nat-header
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_progress_init(2);
	$conf{'nat_header'} = 'X-NAT-Header';
	$conf{'nat_header_type'} = 1;

	t_reload();
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();

	t_smtp_mail_rcpt();
	t_smtp_one('DATA', '354 go ahead');
	t_println_push('cli',
		'From: user@test.test',
		'',
		'.'
	);

	# X-NAT-Header: from [127.0.0.1]:58110 [ident-empty]
	t_expect_regex('srv', '^X-NAT-Header: .*');
	#  by proxy.auto.test with TPROXY id 1126736591.10669
	t_expect_regex('srv', '^\t.*');
	# no abuse header
	t_expect_pop('srv', 3);
	t_println_push('srv', '250 Spool ok');
	t_expect_pop('cli');

	t_smtp_quit();

	# with abuse header set
	$conf{'abuse'} = 'abuse@test.test';

	t_reload();
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();

	t_smtp_mail_rcpt();
	t_smtp_one('DATA', '354 go ahead');
	t_println_push('cli',
		'From: user@test.test',
		'',
		'.'
	);

	# X-NAT-Header: from [127.0.0.1]:58110 [ident-empty]
	t_expect_regex('srv', '^X-NAT-Header: .*');
	# \tby proxy.auto.test with TPROXY id 1126736591.10669
	t_expect_regex('srv', '^\tby .*');
	# \tabuse-to abuse@test.test
	t_expect_regex('srv', '^\tabuse-to .*');
	t_expect_pop('srv', 3);
	t_println_push('srv', '250 Spool ok');
	t_expect_pop('cli');

	t_smtp_quit();
});

# : vim: syntax=perl :
