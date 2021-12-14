#
# fill buffers with junk and check if proxy will get out alive
#

use strict;
use vars qw(%set %conf %defs $prev);


register(sub {
	my $max1 = 20;
	my $max2 = 20;

	$conf{'timeout_session'} = 600;
	$conf{'on_takeover_cmds'} = 100;
	t_reload();
	t_smtp_init();
	t_smtp_ehlo();

	t_progress_init($max1 + $max2);

	for(my $i=1; $i<=$max1; $i++) {
		t_progress_next();

		my $str = chr(0) x (6749+3019*$i);
		t_smtp_one($str, '502 Command unknown [MTA]');

		$str = '$' x (5739+3107*$i);
		t_smtp_one($str, '502 Command unknown [MTA]');
	}

	#
	# now let's check SMTP emulation in taken over session
	#

	t_smtp_mail_rcpt();
	t_smtp_one('DATA', '354 go ahead');
	t_println_push('cli', t_eicar_body());

	t_expect_flush('srv');
	t_expect_closed('srv');

	t_expect_regex('cli', '^550 [a-zA-Z]');

	for(my $i=1; $i<=$max2; $i++) {
		t_progress_next();

	#	my $str = chr(0) x (6749+319*$i);
	#	t_smtp_one($str, '502 Command unknown');

		t_println('cli', chr(0) x (5739+3117*$i));
		t_expect_regex('cli', '^502 ');

		t_println('cli', '$' x (5739+3117*$i));
		t_expect_regex('cli', '^502 ');
	#	t_smtp_one($str, '502 Command unknown');
	}


	t_println('cli', 'QUIT');
	t_expect_regex('cli', '^221 ');
	t_expect_closed('cli');
	t_debug_expect('CHILD_GONE');
});

# : vim: syntax=perl :

