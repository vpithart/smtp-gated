#
# simply pass clean message
#

use strict;
use vars qw (%set %conf %defs $prev);


register(sub {
	my $max = $set{'long'} ? 25 : 5;

	# necessary to allocate some memory
	# makes false memory-leak warning otherwise
	$conf{'lock_duration'} = 60;
	t_reload();

	t_progress_init($max);
	foreach (1..$max) {
		t_progress_next();
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_smtp_send();
		t_smtp_quit();
	}
});

# : vim: syntax=perl :
