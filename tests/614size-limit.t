#
# check if size_limit is properly handled
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	my $line = ("0"x98)."\r\n";
	my $line_length = length($line);
	my @limits = (1000, 5000, 10000, 50000, 100000);

	t_progress_init(1+scalar @limits);
	t_progress_next();
	t_reload();

	# no limit yet
	t_debug('no limit yet');
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send((("0"x98)."\n")x1000);
	t_smtp_quit();

	# set some message size limit
	foreach my $limit (@limits) {
		t_progress_next();
		t_debug('limit: %s', $limit);
		$conf{'size_limit'} = $limit;
		t_reload();

		# limit not reached
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_smtp_send();
		t_smtp_quit();
		
		# hit message limit
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_smtp_data();
		
		for (my $sent = 0;;) {
			t_print($cli, $line);
			$sent += $line_length;
			last if ($sent > $conf{'size_limit'});
			t_expect($srv, $prev);
		}
		
		t_expect_flush('srv');
		t_expect_closed('srv');
		t_expect_regex('cli', '^552 [a-zA-Z]');
		t_println('cli', 'QUIT');
		t_expect_regex('cli', '^221 ');
		t_expect_closed('cli');
		t_debug_expect('CHILD_GONE');
	}
});

# : vim: syntax=perl :

