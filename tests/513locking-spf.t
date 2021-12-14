#
# check if locking works for SPF
#

use strict;
use vars qw(%set %conf @local_ips %defs $prev);

register(sub {
	die "N/A: no SPF support\n" if ($defs{'USE_SPF'} || 'no') eq 'no';
	die "N/A: no alternate IPs\n" unless @local_ips;

	t_debug("Using first IP from: %s", join(', ', @local_ips));
	my $ip = $local_ips[0];

	t_progress_init(5);

	# lock_on: spf
	$conf{'spf'} = 'outgoing';
	$conf{'outgoing_addr'} = $ip;
	$conf{'fixed_server'} = $ip;
	$conf{'spf_log_only'} = 'no';
	t_reload();

	# SPF-pass
	t_progress_next();
	t_smtp_init(undef, undef, $ip);
	t_smtp_ehlo();
	t_smtp_mail_rcpt('<user@pass.spf-test.klolik.org>');
	t_smtp_send();
	t_smtp_quit();

	# SPF-fail (reject), we are not locked still
	t_progress_next();
	t_smtp_init(undef, undef, $ip);
	t_smtp_ehlo();
	t_println('cli', 'MAIL FROM: <user@fail.spf-test.klolik.org>');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# SPF-pass
	t_progress_next();
	t_smtp_init(undef, undef, $ip);
	t_smtp_ehlo();
	t_smtp_mail_rcpt('<user@pass.spf-test.klolik.org>');
	t_smtp_send();
	t_smtp_quit();

	# now fiddle with locking
	$conf{'lock_on'} = 'spf';
	t_reload();

	# SPF-fail again (reject), this time we are locked
	t_progress_next();
	t_smtp_init(undef, undef, $ip);
	t_smtp_ehlo();
	t_println('cli', 'MAIL FROM: <user@fail.spf-test.klolik.org>');
	t_expect('srv', "QUIT\r\n");
	t_expect_closed('srv');
	t_expect_regex('cli', '^550 ');
	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');

	# and now we are really locked
	t_progress_next();
	t_smtp_is_locked(undef, $ip);
	t_lock_remove($ip);
});

# : vim: set syntax=perl :
