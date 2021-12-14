#
# check if script is called when virus found
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	my $max_utime_diff = 10;
	my $action_sleep = 1;
	my $action_log = "$set{path_log}/action.log";
	my $action_dat = "$set{path_log}/action.dat";
	$conf{'action_script'} = "$set{path}/action.sh";
	$conf{'log_mail_from'} = 3;
	$conf{'lock_on'} = 'virus';

	#
	# save our pid for scripting purpose
	open(AP, ">$action_dat") || die "can't write action_dat [$action_dat]: $!\n";
	printf AP "ACTION_PID=%s\n", getpid();
	printf AP "ACTION_SLEEP=%s\n", $action_sleep;
	printf AP "ACTION_LOG=%s\n", $action_log;
	close(AP);

	unlink $action_log;

	#
	# start
	t_reload();

	t_smtp_init();
	t_smtp_helo();
	t_smtp_mail_rcpt();
	t_smtp_send();

	t_smtp_one('RSET', '250 OK');

	t_println_push('cli',
		'MAIL FROM: <user@test.test>',
		'RCPT TO: <user@test.test>',
		'RCPT TO: <user@test.test>',
		'RCPT TO: <user@test.test>',
		'RCPT TO: <user@test.test>',
		'RCPT TO: <user@test.test>'
	);
	t_expect_pop('srv');
	t_println_push('srv', '250 OK') for (1..6);
	t_expect_pop('cli');
	t_eicar_catch();

	# wait while script ends
	# moze zamiast sleep() otworzyc jakis socket, zeby
	# skrypt do niego napisal?
	eval {
		local $SIG{'HUP'} = sub { die "OK\n"; };
		sleep($set{'timeout'});
	};
	die "Not signalled -- script failed to complete.\n" unless ($@ eq "OK\n");

	#unlink $action_log;
	unlink $action_dat;

	t_lock_remove();
});

# : vim: syntax=perl :
