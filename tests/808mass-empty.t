#
# mass empty connections
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	my $max = $set{'long'} ? 10000 : 100;

	t_progress_init($max);
	t_reload();

	for(my $i=1; $i<=$max; $i++) {
		t_progress_next();
		t_smtp_init();
		t_smtp_quit();
	}

	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_eicar_catch();
});

# : vim: set syntax=perl :

