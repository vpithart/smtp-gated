#
# check for many connections (memory leaks mostly)
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	my $max = $set{'long'} ? 10000 : 50;
	t_progress_init($max);
	t_reload();

	t_progress_next();
	for(my $i=1; $i<$max; $i++) {
		t_smtp_init();
		t_smtp_ehlo();
#		t_smtp_mail_rcpt();
#		t_smtp_send();
		t_smtp_quit();
		t_progress_next();
	}
});

# : vim: syntax=perl :

