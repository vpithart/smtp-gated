#
# 
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	die "TODO\n";

	my $max = 20;
	t_progress_init($max);
	#$max = 1025;

	t_reload();
	t_smtp_init();
	t_smtp_ehlo();

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
});

# : vim: syntax=perl :

