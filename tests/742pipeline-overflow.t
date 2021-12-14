#
# test pipeline-full reaction
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_progress_init(4);

	sub pipe_check()
	{
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();

		for (my $i=1; $i<$conf{'pipeline_size'}; $i++) {
			t_println_push('cli', 'RCPT TO: <user@test.test>');
		}
	#	t_expect('cli', '.*');
		t_expect_nothing('cli');

		t_println('cli', 'RCPT TO: <user@test.test>');
		t_expect_regex('cli', '^503 [a-zA-Z]+');
		
		t_expect_pop('srv', 0);
		t_expect_regex('srv', '^QUIT');
		t_expect_closed('srv');

		t_println('cli', 'QUIT');
		t_expect_regex('cli', '^221 [a-zA-Z]');
		t_expect_closed('cli');
		t_debug_expect('CHILD_GONE');
	}

	$conf{'pipeline_size'} = 16;
	t_reload();
	t_progress_next();
	pipe_check();

	$conf{'pipeline_size'} = 64;
	t_reload();
	t_progress_next();
	pipe_check();

	$conf{'pipeline_size'} = 256;
	t_reload();
	t_progress_next();
	pipe_check();

	$conf{'pipeline_size'} = 1024;
	t_reload();
	t_progress_next();
	pipe_check();
});

# pipeline - zobaczyc czy zostawi spoola po zerwaniu
# polaczenia, przy leave_on_error
__END__

for ($i=1; $i<$max; $i++) {
	$rcpt .= sprintf("RCPT TO: test%s@test.test\r\n", $i);
}

t_println('cli', $rcpt);
t_expect_regex('srv', ...);

for ($i=1; $i<$max; $i++) {
	$rcpt .= sprintf("250 OK\r\n");
}
t_println('srv');
t_expect_regex('cli', ...);


# : vim: syntax=perl :
