#
# mass send/lock/etc
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	die "TODO\n";

	my $max = $set{'long'} ? 20000 : 500;
	my $rej_code = $defs{'CONN_REJ_CODE'};

	#die "LONG\n" unless $set{'long'} or $max <= 500;

	$conf{'lock_duration'} = 7200;
	t_progress_init($max);


	t_reload();

	# issue lock
	t_smtp_init();
	t_smtp_ehlo();

	t_smtp_mail_rcpt();
	t_eicar_catch();

	# test many locked connections
	for(my $i=1; $i<=$max; $i++) {
		t_progress_next();

		eval {
			local $SIG{'USR1'} = sub { die "OK\n"; };
			t_connect('cli');
			t_expect_regex('cli', "^$rej_code ");
			t_expect_closed('cli');
			t_debug_expect('CHILD_GONE');
		};

		die $@ if ($@ ne "OK\n");
	}
});

# : vim: set syntax=perl :
