#
# check for multi transaction session
# with virus detection
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	my $max = 30;
	t_progress_init($max);
	#$max = 1025;

	t_reload();
	t_smtp_init();
	t_smtp_ehlo();

	#local %conf;

	for(my $i=1; $i<$max; $i++) {
		t_progress_next();

		t_smtp_mail_rcpt();
		t_smtp_send();
		t_smtp_one('RSET', '250 OK');
	}

	#
	# now the virus
	t_progress_next();

	t_smtp_mail_rcpt();
	t_eicar_catch();

	# proxy-response, so needs to be removed
	#t_smtp_quit();
});

# : vim: syntax=perl :

