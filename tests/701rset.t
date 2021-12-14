#
# check for cancelled transaction
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_reload();
	t_smtp_init();
	t_smtp_ehlo();

	t_smtp_mail_rcpt();
	t_smtp_one('DATA', '451 temporary problem');

	# next transaction
	t_smtp_one('RSET', '250 OK');
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();
});

# : vim: syntax=perl :
