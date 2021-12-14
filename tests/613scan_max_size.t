#
# check for proper message size limit
#

use strict;
use vars qw(%set %conf %defs);

register(sub {
	# 1. eicar
	# 2. max_scan_size = 2, reload
	# 3. eicar

	t_reload();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_eicar_catch();

	#
	# now eicar should pass
	#

	$conf{'scan_max_size'} = 5;
	t_reload();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_eicar_pass();
	t_smtp_quit();
});

# : vim: syntax=perl :


