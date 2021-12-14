#
# check limit per host connections (max_per_host)
#
# TODO: verify two-stage lock verification (on connect, after data)

use strict;
use vars qw(%set %conf %defs);

register(sub {
	# some OS don't allow to bind to 127.0.0.x other than 127.0.0.1
	unless ($set{'alt_ip_ok'}) {
		t_debug('no alternate IP available - test skipped');
		die "N/A: no alternate loopback IPs\n";
	}

	# max_connections can NOT be changed without full restart
	die "conf{max_connections} less than 4!\n" if ($conf{'max_connections'} < 4);

	$conf{'max_per_host'} = 1;
	t_reload();

	t_smtp_init('cli-1a', 'srv-1a', $set{'src_ip'});
	t_smtp_ehlo();

	t_smtp_init('cli-2', 'srv-2', $set{'src_ip_alt'});
	t_smtp_ehlo();

	# these should fail
	t_smtp_is_locked('cli-1b', '127.0.0.1');
	t_smtp_is_locked('cli-1c', '127.0.0.1');

	t_connect('cli-1d', '127.0.0.1');
	t_connect('cli-1e', '127.0.0.1');
	t_expect_regex('cli-1d', '^554 ');
	t_expect_regex('cli-1e', '^554 ');
	t_expect_closed('cli-1d');
	t_expect_closed('cli-1e');

	# t_change('cli-2', 'srv-2');
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	t_change('cli-1a', 'srv-1a');
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();


	# create 3rd connection from 1st host
	# create 3rd connection from 2nd host

	# now check more
	#$conf{'max_per_host'} = 2;
	#t_reload();
	#
	#t_smtp_init('cli-1a', 'srv-1a', $set{'src_ip'});
	#t_smtp_ehlo();
	#
	#t_smtp_init('cli-2', 'srv-2', $set{'src_ip_alt'});
	#t_smtp_ehlo();
	#
	## these should fail
	#t_smtp_is_locked('cli-1b', '127.0.0.1');
	#t_smtp_is_locked('cli-1c', '127.0.0.1');
	#
	#t_connect('cli-1d', '127.0.0.1');
	#t_connect('cli-1e', '127.0.0.1');
	#t_expect_regex('cli-1d', '^554 ');
	#t_expect_regex('cli-1e', '^554 ');
	#t_expect_closed('cli-1d');
	#t_expect_closed('cli-1e');
});

# : vim: syntax=perl :

