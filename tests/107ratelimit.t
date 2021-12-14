#
# ratelimit test
#

use strict;
use vars qw(%set %conf);

register(sub {
	local $set{'timeout'} = 3;
	eval {
		t_ratefile_remove();
	};

	t_progress_init(8);
	$conf{'ratelimit_expiration'} = 60;
	$conf{'ratelimit_generation'} = 0;
	$conf{'ratelimit_connections'} = 4;
	t_reload();

	for (1..$conf{'ratelimit_connections'}) {
		t_progress_next();
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_smtp_send();
		t_smtp_quit();
	}
	t_smtp_is_ratelimited();

	for (1..4) {
		t_progress_next();
		# force reload quota settings from config
		$conf{'ratelimit_generation'}++;
		$conf{'ratelimit_connections'}++;
		t_reload();

		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_smtp_send();
		t_smtp_quit();
		
		t_smtp_is_ratelimited();
	}

	t_ratefile_remove();

	# messages
	# recipients
	# bytes
	# destinations
	# MAIL FROMs
	# RCPT TOs
	# IPs
	die "TODO\n";
});

# : vim: syntax=perl :
