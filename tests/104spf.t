#
# SPF check
#

use strict;
use vars qw(%set %conf @local_ips %defs $prev);

register(sub {
	die "N/A: no SPF support\n" if ($defs{'USE_SPF'} || 'no') eq 'no';
	die "N/A: no alternate IPs\n" unless @local_ips;

	use constant NONE => 0;
	use constant HELO => 1;
	use constant EHLO => 2;

	sub helo($)
	{
		t_smtp_helo() if ($_[0] == HELO);
		t_smtp_ehlo() if ($_[0] == EHLO);
	}


	t_debug("Using first IP from: %s", join(', ', @local_ips));
	my $ip = $local_ips[0];

	t_progress_init(19);

	# spf: outgoing
	# outgoing_addr: must be local address, other than loopback
	# 127.0.0.1 is never rejected by SPF
	$conf{'spf'} = 'outgoing';
	$conf{'outgoing_addr'} = $ip;
	$conf{'fixed_server'} = $ip;
	t_reload();

	foreach my $mode (NONE, HELO, EHLO) {
		# no SPF record
		t_progress_next();
		t_smtp_init(undef, undef, $ip);
		helo($mode);
		t_smtp_mail_rcpt('user@none.spf-test.klolik.org', 'user@example.com');
		t_smtp_send();
		t_smtp_quit();

		# SPF passed
		t_progress_next();
		t_smtp_init(undef, undef, $ip);
		helo($mode);
		t_smtp_mail_rcpt('user@pass.spf-test.klolik.org', 'user@example.com');
		t_smtp_send();
		t_smtp_quit();

		# SPF neutral
		t_progress_next();
		t_smtp_init(undef, undef, $ip);
		helo($mode);
		t_smtp_mail_rcpt('user@neutral.spf-test.klolik.org', 'user@example.com');
		t_smtp_send();
		t_smtp_quit();

		# SPF soft-fail
		t_progress_next();
		t_smtp_init(undef, undef, $ip);
		helo($mode);
		t_smtp_mail_rcpt('user@soft.spf-test.klolik.org', 'user@example.com');
		t_smtp_send();
		t_smtp_quit();

		# SPF-fail (reject)
		t_progress_next();
		t_smtp_init(undef, undef, $ip);
		helo($mode);
		t_println('cli', 'MAIL FROM: <user@fail.spf-test.klolik.org>');
		t_expect('srv', "QUIT\r\n");
		t_expect_closed('srv');
		t_expect_regex('cli', '^550 ');
		t_println('cli', 'QUIT');
		t_expect_regex('cli', '^221 ');
		t_expect_closed('cli');
		t_debug_expect('CHILD_GONE');

		# no SPF record again, we should not got locked
		t_progress_next();
		t_smtp_init(undef, undef, $ip);
		helo($mode);
		t_smtp_mail_rcpt('user@none.spf-test.klolik.org', 'user@example.com');
		t_smtp_send();
		t_smtp_quit();
	}

	# spf_log_only: SPF result is fail (just like above), but should pass anyway
	$conf{'spf_log_only'} = 'yes';
	t_reload();

	t_progress_next();
	t_smtp_init(undef, undef, $ip);
	t_smtp_ehlo();
	t_smtp_mail_rcpt('user@fail.spf-test.klolik.org', 'user@example.com');
	t_smtp_send();
	t_smtp_quit();

	# spf: origin
	$conf{'spf'} = 'outgoing';
	t_reload();
	die "TODO\n";


	# MAIL FROM: <>
	die "TODO\n";
	#t_smtp_init(undef, undef, $ip);
	#t_smtp_ehlo();
	#t_println('cli', 'MAIL FROM: <>');
	#t_expect('srv', "QUIT\r\n");
	#t_expect_closed('srv');
	#t_expect_regex('cli', '^550 ');
	#t_println('cli', 'QUIT');
	#t_expect_regex('cli', '^221 ');
	#t_expect_closed('cli');
});

# : vim: set syntax=perl :

