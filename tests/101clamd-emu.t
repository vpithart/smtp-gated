#
# check if virus is blocked
#

use strict;
use vars qw(%set %conf %defs $prev);


register(sub {
	t_reload();
	t_smtp_init();
	t_smtp_ehlo();

	t_smtp_mail_rcpt();
	t_eicar_catch();
});

# : vim: syntax=perl :

