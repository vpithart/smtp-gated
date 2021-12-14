#
# check for multi transaction session
# with virus detection
#

use strict;
use vars qw(%set %conf %defs $prev);


register(sub {
	my $max = 30;	# 100
	$conf{'max_per_host'} = $max;
	t_reload();

	t_spawn($max, sub {
		my $n = shift;
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_smtp_send();

		t_println('cli', 'QUIT');
		t_expect('srv', $prev);
		t_println('srv', '221 Bye bye');
		t_expect('cli', $prev);

		t_close('srv');
		t_expect_closed('cli');

	});

	t_debug_expect('CHILD_GONE') for (1..$max);
});

# : vim: syntax=perl :

