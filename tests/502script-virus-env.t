#
# check if script is called when virus found
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	die "N/A: setenv not supported\n" if ($defs{'HAVE_SETENV'} || '') eq 'no';

	our $max_utime_diff = 10;
	our $action_log = "$set{path_log}/action.log";
	my $action_sleep = 0;
	my $action_dat = "$set{path_log}/action.dat";
	my $action_script = "$set{path}/action.sh";

	$conf{'action_script'} = $action_script;
	$conf{'log_mail_from'} = 3;
	$conf{'scan_max_size'} = 100000;
	$conf{'lock_on'} = 'virus';
	$conf{'lock_duration'} = 300;

	#
	# save our pid for scripting purpose
	open(AP, ">$action_dat") || die "can't write action_dat [$action_dat]: $!\n";
	printf AP "ACTION_PID=%s\n", getpid();
	printf AP "ACTION_SLEEP=%s\n", $action_sleep;
	printf AP "ACTION_LOG=%s\n", $action_log;
	close(AP);

	sub check($)
	{
		my ($helo) = @_;

		unlink $action_log;

		t_progress_next();
		t_smtp_init();
		t_smtp_helo($helo);
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
			# USR1
			local $SIG{'HUP'} = sub { die "OK\n"; };
			sleep($set{'timeout'});
		};
		die "Not signalled -- script failed to complete.\n" unless ($@ eq "OK\n");

		my %kv;
		open(ACTION_LOG, $action_log) || die "can't open action log [$action_log]: $!\n";
		while (defined($_=<ACTION_LOG>)) {
			chomp;
			my ($key, $val) = split /=/, $_, 2;
			$kv{$key} = $val;
		}
		close(ACTION_LOG);

		die "invalid PROXY_NAME!\n" unless ($kv{'PROXY_NAME'} eq $conf{'proxy_name'});
		die "invalid UNIXTIME!\n" unless ($kv{'UNIXTIME'} =~ m%^[0-9]+$%);
		die "UNIXTIME out of range!\n" if ($kv{'UNIXTIME'} - time() > $max_utime_diff);
	#	die "invalid TIME!\n" unless ($kv{'TIME'} eq localtime($kv{'UNIXTIME'}));
		die "invalid FOUND!\n" unless ($kv{'FOUND'} eq 'VIRUS');
		die "invalid VIRUS_NAME!\n" unless ($kv{'VIRUS_NAME'} eq 'Clamd-Emu-Test-Signature');
		die "invalid SPAM_SCORE!\n" unless ($kv{'SPAM_SCORE'} eq '0.000');
		die "invalid SOURCE_IP!\n" unless ($kv{'SOURCE_IP'} eq '127.0.0.1');
		die "invalid TARGET_IP!\n" unless ($kv{'TARGET_IP'} eq '127.0.0.1');
		die "invalid LOCAL_IP!\n" unless ($kv{'LOCAL_IP'} eq '127.0.0.1');
		die "invalid SOURCE_PORT!\n" unless ($kv{'SOURCE_PORT'} =~ m%^[0-9]+$%);
		die "invalid TARGET_PORT!\n" unless ($kv{'TARGET_PORT'} eq $conf{'fixed_server_port'});
		die "invalid LOCAL_PORT!\n" unless ($kv{'LOCAL_PORT'} eq $conf{'port'});
		die "invalid LOCK_DURATION!\n" unless ($kv{'LOCK_DURATION'} eq $conf{'lock_duration'});

		die "invalid IDENT!\n" unless ($kv{'IDENT'} eq '');
		die "invalid IDENT_COUNT!\n" unless ($kv{'IDENT_COUNT'} eq '0');
		die "invalid HELO!\n" unless ($kv{'HELO'} eq $helo);
		die "invalid MAIL_FROM!\n" unless ($kv{'MAIL_FROM'} eq 'user@test.test');
		die "invalid RCPTS_TOTAL!\n" unless ($kv{'RCPTS_TOTAL'} eq '6');
		die "invalid SIZE!\n" unless ($kv{'SIZE'} =~ /^[0-9]+$/);
		die "invalid TRANSACTION!\n" unless ($kv{'TRANSACTION'} eq '2');
		die "invalid SPOOL_NAME!\n" unless ($kv{'SPOOL_NAME'} =~ m%^$conf{spool_path}/$kv{UNIXTIME}\.[0-9]+$%);
		die "invalid LOCK_FILE!\n" unless ($kv{'LOCK_FILE'} eq $set{'lock'});

		t_lock_remove();
	}

	t_reload();
	t_progress_init(3);
	check('host1.example.com');
	check('host2.example.com');
	check('abrakadabra.com');

	unlink $action_dat;
});


# TIME=Fri Sep 16 17:46:32 2005
# PROXY_NAME=$conf{'proxy_name'}
# UNIXTIME=1126885592
# FOUND=VIRUS
# VIRUS_NAME=Clamd-Emu-Test-Signature
# SPAM_SCORE=0.000000
# SOURCE_IP=127.0.0.1
# SOURCE_PORT=37699
# TARGET_IP=127.0.0.1
# TARGET_PORT=2111
# LOCAL_IP=127.0.0.1
# LOCAL_PORT=2121
# IDENT=
# IDENT_COUNT=0
# HELO=host.example.com
# MAIL_FROM=user@test.test
# RCPTS_TOTAL=6
# SIZE=295
# TRANSACTION=2
# SPOOL_NAME=/home/bartek/prog/c/smtp-gated/tests/msg/1126885592.9488
# LOCK_FILE=/home/bartek/prog/c/smtp-gated/tests/lock/127.0.0.1

# : vim: syntax=perl :
