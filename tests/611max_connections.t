#
# check limit on total connections (max_connections)
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	my ($max, $over, $i);


	$max = $conf{'max_connections'};
	$over = $max+1;

	# some OS don't allow to bind to 127.0.0.x other than 127.0.0.1
	unless ($set{'alt_ip_ok'}) {
		t_debug('no alternate IP available - test skipped');
		die "N/A: no alternate loopback IPs\n";
	}
	# max_connections can NOT be changed without full restart
	#die "conf{max_connections} not set to 4!\n" if ($max != 4);

	$conf{'max_per_host'} = $max + 10;
	t_reload();
	t_progress_init($max);

	for ($i=1; $i<=$max; $i++) {
		t_smtp_init("cli-$i", "srv-$i", "127.0.0.$i");
		t_smtp_helo();
	}

	t_smtp_is_locked('cli-x', "127.0.0.$over");

	for ($i=1; $i<=$max; $i++) {
		t_progress_next();
		t_change("cli-$i", "srv-$i");
		t_smtp_mail_rcpt();
		t_smtp_send();
		t_smtp_quit();
	}
});

# : vim: syntax=perl :

