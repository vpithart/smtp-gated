#
# multiple DNSBL checks
#
# NOTICE: DNS resolver configuration, especially "search domain.com" keyword
# with catch-all domains in /etc/resolv.conf may cause this test to fail
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_progress_init(5);

	# the following is setup to list 127.0.0.1 as blacklisted
	my $dnsbl = 'dnsbl-test.klolik.org';

	#
	# not found, not rejected
	#
	$conf{'dnsbl'} = 'none.dnsbl-test.klolik.org';
	$conf{'auth_skip'} = 'none';
	t_reload();

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	#
	# not authentication, so reject after connect()
	#
	$conf{'dnsbl'} = $dnsbl;
	t_reload();

	t_progress_next();
	t_smtp_is_locked();
	t_debug_expect('CHILD_GONE');

	#
	# no auth, reject
	#
	$conf{'auth_skip'} = 'dnsbl';
	t_reload();

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo();
	t_println('cli', 'MAIL FROM: <user@test.test>');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	#
	# auth not advertised, not authenticated, reject
	#
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_println('cli', 'MAIL FROM: <user@test.test>');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	#
	# authenticated, passed
	#
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_auth();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();
});

# : vim: set syntax=perl :

