#
# check overall validity of state files (i.e. junk characters)
#

use strict;
use vars qw(%set %conf %defs $prev $path);

register(sub {
	my $max = $set{'long'} ? 100 : 10;

	t_reload();

	sub statefile_verify()
	{
		open(F, $conf{'statefile'}) || die "can't open statefile: $!\n";
		while (defined($_=<F>)) {
			chomp;
			die "unacceptable characters in statefile! [$_]\n" unless m%^[0-9a-zA-Z:;()/_. -]*$%o;
		}
		close(F);
	}


	t_progress_init($max);
	foreach (1..$max) {
		t_progress_next();
		unlink $conf{'statefile'} if -f $conf{'statefile'};

		# we check more than once, so coredumps should crash
		# this test too
		t_smtp_init();
		t_smtp_ehlo(auth => 1);
		t_smtp_auth();
		t_signal(SIGUSR1);
		t_smtp_send();
		t_smtp_quit();
		sleep(0.5);

		# leave last dump for human inspection
		statefile_verify();
	}
});

# : vim: syntax=perl :
