#
# send message without issuing HELO/EHLO
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_reload();

	t_smtp_init();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();
});

# : vim: syntax=perl :

