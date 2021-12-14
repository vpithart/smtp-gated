#
# mass send/lock/etc
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	my $max = $set{'long'} ? 5000 : 20;

	t_reload();
	t_progress_init($max);

	for(my $i=1; $i<=$max; $i++) {
		t_progress_next();
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_smtp_send();
		t_smtp_quit();
	}
});

# : vim: set syntax=perl :

