#!/usr/bin/perl -w

use strict;
use IO::Socket;
use IO::Select;
use IO::File;
use POSIX;


use vars qw($pid_sp $reuse $fd_sp $test_name);
use vars qw(%defs %conns %set %conf %initconf $reloads);
use vars qw($cli $srv $prev @pipe);
use vars qw($pid_clamd_emu $pid_spamd_emu);
use vars qw($progress_max $progress_cur);

$reuse = 'Reuse';
# $reuse = 'ReuseAddr';


#
# misc
#

sub stack_trace()
{
    my $i = 1;
    my $trace = "--- BEGIN STACK TRACE ---\n";
    for ($i=1; $i<=32; $i++) {
        my @det = caller($i++) or last;
        $trace .= join(':', map { defined($_) ? $_ : 'undef' } @det) . "\n";
    }
    $trace .= "--- END STACK TRACE ---\n";
    return $trace;
}

sub error($@)
{
	my $format = shift;
	die(sprintf $format, @_);
}

sub mdebug($@)
{
	return unless $set{'debug'};
	my $format = shift;

	printf STDERR " # $format\n", @_;
}

sub t_sleep($)
{
	my ($time) = @_;
	select(undef, undef, undef, $time);
}

sub t_debug($@)
{
	my $format = shift;
	mdebug("debug: $format", @_);
}

sub t_echo($@)
{
	my $format = shift;
	printf $format, @_;
}

sub i_printable($)
{
	my $str = $_[0];

	$str =~ s%\r%\\r%go;
	$str =~ s%\n%\\n%go;

	return $str;
}

sub i_progress($)
{
	my ($val) = @_;
	printf "\rrunning %-32s ... %s", $test_name, $val;
}

sub i_progress_done($)
{
	my $quiet = shift;

	return unless defined $progress_max;
	die "Progress counter mismatch!" unless $quiet or $progress_max == $progress_cur;
	undef $progress_max;
}

#sub t_progress($$)
#{
#	i_progress("\[$_[0]/$_[1]\]");
#}

sub t_progress_init($)
{
	die "Progress counter not finished!" if defined $progress_max;

	$progress_max = $_[0];
	$progress_cur = 0;
}

sub t_progress_next()
{
	die "Progress counter error!" unless defined $progress_max;
	$progress_cur++;
	printf STDERR " # t_progress: %s/%s\n", $progress_cur, $progress_max;
	i_progress sprintf('[%s/%s]', $progress_cur, $progress_max);
}


#
# process
#

sub t_debug_expect(;$)
{
	my $wait_for = shift || '';

	my $got;
	eval {
		local $SIG{'ALRM'} = sub { die "t_debug_expect[$wait_for]: timeout\n"; };
		alarm($set{'process_timeout'});
		for (;;) {
			$got = <$fd_sp>;
			last unless defined $got;
			chomp $got;
			next unless $got =~ m%^DEBUG-STAGE:(.*)$%o;
			$got = $1;
			last;
		} 
		alarm(0);
		mdebug('t_debug_expect: got [%s]', defined($got) ? $got : '(undef)');
		die "t_debug_expect: got [$got] instead of [$wait_for]\n" if $wait_for and $got !~ $wait_for;
	};
	die $@ if $@;

	return $got;
}

sub t_signal($)
{
	my $signal = $_[0];
	mdebug('t_signal %s, %s', $signal, $pid_sp);

	kill($signal, $pid_sp) || die "t_signal($signal, $pid_sp): $!\n";
}

sub t_wait()
{
	mdebug('t_wait');
	eval {
		local $SIG{'ALRM'} = sub { die "t_wait timeout!\n"; };
		alarm($set{'process_timeout'});
		wait();
		alarm(0);
	};
}

sub t_spawn_proxy()
{
	my $arg;
	$arg = "$set{wrapper} $set{bin} $set{args} $set{conf} $set{redir}";
	mdebug('t_spawn [%s]', $arg);

	$fd_sp = new IO::File;
	$pid_sp = open($fd_sp, "$arg |");
	die "t_spawn: $!" unless $pid_sp;

	t_debug_expect('READY');
	
	open(PID, $conf{'pidfile'}) || die "open($conf{pidfile}): $!\n";
	$pid_sp = <PID>;
	close(PID);

	chomp($pid_sp);

	mdebug('t_spawn:pid: %s', $pid_sp);
}

sub i_save_config()
{
	open(CONF, ">$set{conf}") || die "t_reload: save config($set{conf}): $!";
	foreach (keys %conf) {
		printf CONF "%-24s\t%s\n", $_, $conf{$_};
	}
	close(CONF);
}

sub t_reload()
{
	mdebug('t_reload');

	i_save_config();
	t_signal(1); # SIGHUP
	t_debug_expect('READY');
	$reloads++;
	mdebug('t_reload done');
}

sub t_lock_remove(;$)
{
	my $ip = shift || $set{'src_ip'};

	die "t_lock_remove: strange IP [$ip]!\n" unless ($ip =~ m%^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$%o);

	my $fn = $conf{'lock_path'} . '/' . $ip;
	die "t_lock_remove: lock [$fn] not found!\n" unless (-f $fn);

	mdebug("t_lock_remove: %s", $fn);
	unlink $fn;
}

sub t_ratefile_remove(;$)
{
	my $ip = shift || $set{'src_ip'};

	die "t_ratelimit_remove: strange IP [$ip]!\n" unless ($ip =~ m%^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$%o);

	my $fn = $conf{'ratelimit_path'} . '/' . $ip;
	die "t_ratelimit_remove: lock [$fn] not found!\n" unless (-f $fn);

	mdebug("t_ratelimit_remove: %s", $fn);
	unlink $fn || mdebug("unlink $fn failed: $!");
}

sub i_list_locks()
{
	opendir(LOCKS, $conf{'lock_path'});
	my @locks = grep { !m%^\.%o } readdir(LOCKS);
	closedir(LOCKS);

	return @locks;
}

sub i_lock_cleanup()
{
	foreach (i_list_locks()) {
		if (m%^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$%o) {
			mdebug("i_lock_cleanup: %s", $_);
			unlink $conf{'lock_path'} . '/' . $_;
		} else {
			die "i_lock_cleanup: strange lock left: [$_], not unlinking!\n";
		}
	}
}

sub t_init_config()
{
	%conf = %initconf;
}

#
# fake servers
#

sub spawn_server($&)
{
	my ($pid, $lsock, $sock, $res);
	my ($name, $helper) = @_;

	$pid = fork();
	die "spawn_server:fork($name) failed: $!\n" if ($pid < 0);
	return $pid if $pid;

	$0 = "$0 [".$name."_emu]";

	t_close_all();
	select(STDOUT); $| = 1;
	select(STDERR); $| = 1;

	# child

	eval {
		$lsock = IO::Socket::INET->new(Proto=>'tcp', Listen=>16, $reuse=>1,
			LocalAddr=>$set{"ip_$name"}, LocalPort=>$set{"port_$name"});

		die "IO::Socket::INET->new: $!\n" unless $lsock;

		for (;;) {
			$sock = $lsock->accept();

			$res = fork();
			if ($res > 0) {
				$sock->close();
				next;
			}
			die "spawn_server:child fork() failed: $!\n" if ($res < 0);

			$0 = "$0 child";

			select(STDOUT); $| = 1;
			select(STDERR); $| = 1;
			close($lsock);

			$sock->autoflush();
			&$helper($sock);

			$sock->close();
			exit(0);
		}
	};
	if ($@) {
		mdebug("! $name FAIL: $@\n");
		kill(SIGUSR2, getppid());
	}

	exit(0);
}

sub i_spawn_clamd_emu()
{
	return if ($pid_clamd_emu);

	$pid_clamd_emu = spawn_server 'clamd', sub {
		my $sock = $_[0];
		my $eicar = eicar_signature();
		my $is_virus = 0;
	
		# SCAN filename\n
		$_ = <$sock>;

		if (!/^SCAN (.*)\n$/) {
			print $sock "none: invalid_query ERROR\n";
			return;
		}

		my $filename = $1;

		if (!open(FILE, $filename)) {
			print $sock "$filename: $! ERROR\n";
			return;
		}
		while (defined($_=<FILE>)) {
			tr%\r\n%%d;
			$is_virus = 1 if ($_ eq $eicar);
		}
		close(FILE);

		my $response = ($is_virus) ? 'Clamd-Emu-Test-Signature FOUND' : 'OK';

		mdebug("clamd_emu: $response [$filename]");
		print $sock "$filename: $response\n" || die "clamd_emu: can't write response!\n";
	};
}

sub i_spawn_spamd_emu()
{
	return if ($pid_spamd_emu);

	$pid_spamd_emu = spawn_server 'spamd', sub {
		my $sock = $_[0];
		my $gtube = gtube_signature();
		my $is_spam = 0;

		# CHECK SPAMC/1.2\r\n
		$_ = <$sock>;
		unless (m%^CHECK SPAMC/(.*)\r\n%) {
			print $sock "ERROR\n";
			return;
		}
		my $version = $1;
		my ($score, $thr);
		$score = $thr = 10;

		while (defined($_=<$sock>)) {
			tr%\r\n%%d;
			$is_spam = 1 if ($_ eq $gtube);
			$score = $1 if (/^Score: (.*)$/);
			$thr = $1 if (/^Thr: (.*)$/);
		}

		$score = -2.5 unless $is_spam;

		# SPAMD/%s 0 EX_OK\r\nSpam: %*s ; %lf / %lf \r\n
		my $response = sprintf "SPAMD/%s 0 EX_OK\r\nSpam: %s ; %s / %s \r\n",
			$version, $is_spam ? 'True' : 'False', $score, $thr;

		mdebug('spamd_emu: ' . i_printable($response));
		print $sock "$response" || die "spamd_emu: can't write response!\n";
	};
}

sub i_kill_clamd_emu()
{
	return unless defined($pid_clamd_emu);

	mdebug('i_kill_clamd_emu');
	kill(15, $pid_clamd_emu) || die "i_kill_clamd_emu: $!\n";
	$pid_clamd_emu = undef;
}

sub i_kill_spamd_emu()
{
	return unless defined($pid_spamd_emu);

	mdebug('i_kill_spamd_emu');
	kill(15, $pid_spamd_emu) || die "i_kill_spamd_emu: $!\n";
	$pid_spamd_emu = undef;
}

# process configuration


#
# network
#

sub t_spawn($&)
{
	my ($count, $helper) = @_;
	my $errors = 0;

	eval {
		local $SIG{'CHLD'} = 'DEFAULT';
		my %pids;
		for my $i (1..$count) {
			my $pid = fork();
			$pids{$pid} = $i;
			die "t_spawn:fork() failed: $!\n" unless defined $pid;
			next if $pid;

			# child
			mdebug("spawned [%s/%s] pid %s", $i, $count, $$);
			$0 = "$0 child $i/$count";
			select(STDOUT); $| = 1;
			select(STDERR); $| = 1;
			eval {
				&$helper($i);
			};
			mdebug("helper failed: $@\n") if $@;
			exit($@ ? 1 : 0);
		}
		for (;;) {
#			mdebug("t_spawn left: %s [%s]\n", scalar keys %pids, join(' ', keys %pids));
			last unless scalar keys %pids;
			my ($pid, $res) = (waitpid(-1, 0), $?);
			die "t_spawn:waitpid(): $!\n" unless defined $pid;
			delete $pids{$pid};
			next unless $res;
			mdebug("t_spawn: kid %s returned non-zero: %s\n", $pid, $res);
			$errors++;
		}
	};
	die "t_spawn: $errors/$count handler(s) returned error\n" if $errors;
}

sub t_listen()
{
	mdebug('listen %s:%s', $set{'ip_mta'}, $set{'mta_port'});

	return if defined($conns{'*'});

	$conns{'*'} = IO::Socket::INET->new(Proto=>'tcp', Listen=>16, $reuse=>1,
		LocalAddr=>$set{'ip_mta'}, LocalPort=>$set{'mta_port'});

	unless (defined($conns{'*'})) {
		delete $conns{'*'};
		die "t_listen: $!";
	}
}

sub t_connect($;$)
{
	my ($name, $srcip) = @_;
	$srcip = $set{'src_ip'} unless defined($srcip);

	mdebug('connect %s (%s:%s)', $name, $conf{'bind_address'}, $conf{'port'});

	$conns{$name} = IO::Socket::INET->new(Proto=>'tcp', LocalHost=>$srcip,
		PeerAddr=>$conf{'bind_address'}, PeerPort=>$conf{'port'});

	unless (defined($conns{$name})) {
		delete $conns{$name};
		die "t_connect: $!\n"
	}

	$conns{$name}->autoflush(1);
}

sub t_close($)
{
	my ($name) = @_;
	mdebug('close %s', $name);

	$conns{$name}->close();
	delete $conns{$name};
}

sub t_close_all()
{
	mdebug('close_all');
	foreach (keys %conns) {
		$conns{$_}->close();
		delete $conns{$_};
	}
#	t_sleep($set{'close_delay'});
}

sub t_accept($)
{
	my ($name) = @_;
	mdebug('t_accept [%s]', $name);

	eval {
		local $SIG{'ALRM'} = sub { die "t_accept[$name] timeout!\n"; };

		alarm($set{'timeout'});
		$conns{$name} = $conns{'*'}->accept();
		alarm(0);
	};

	die if $@;
	unless (defined($conns{$name})) {
		delete $conns{$name};
		die "t_accept: $!"
	}

	$conns{$name}->autoflush(1);
}

sub t_print($$)
{
	my ($name, $str) = @_;
	my $handle = $conns{$name};

	die "handle '$name' not open!\n" unless defined($handle);

	mdebug('print to [%s] string [%s]', $name, i_printable($str));

	print $handle $str;
	$prev = $str;
}

sub t_printf($$;@)
{
	my ($name, $format, @args) = @_;
	t_print($name, sprintf($format, @args));
}

sub t_println($@)
{
	my ($name, @lines) = @_;

	t_print($name, join('', map { "$_\r\n" } @lines));
}

sub t_println_push($@)
{
	my ($name, @lines) = @_;

	@lines = map { "$_\r\n" } @lines;
	t_print($name, join('', @lines));
	push @pipe, @lines;
}

sub i_expect($$$)
{
	my ($name, $regex, $is_regex) = @_;
	my $handle = $conns{$name};
	die "handle '$name' not open!\n" unless defined($handle);

	my $f = $is_regex ? 't_expect_regex' : 't_expect';

	my $cregex = i_printable($regex);
	mdebug('%s from [%s] expect [%s]', $f, $name, $cregex);

	my $line;
	eval {
		local $SIG{'ALRM'} = sub { die "$f($name,[$cregex]) timeout!\n"; };
		alarm($set{'timeout'});
		$line = <$handle>;
		alarm(0);
	};

	die $@ if ($@);
	die "$f($name): undefined\n" unless defined($line);

	my $cstr = i_printable($line);
	mdebug('%s from [%s] got [%s]', $f, $name, $cstr);

	my $result = ($is_regex) ? ($line =~ /$regex/) : ($line eq $regex);
	die "$f($name): expected [$cregex] but got [$cstr]!" unless $result;
}

sub t_expect($$)
{
	my ($name, $text) = @_;
	i_expect($name, $text, 0);
}

sub t_expect_regex($$)
{
	my ($name, $regex) = @_;
	i_expect($name, $regex, 1);
}


# $n = 'all'
sub t_expect_pop($;$)
{
	my ($name, $n) = @_;

	$n = 1 unless defined($n);
	$n = $#pipe if ($n == 0);

	for (; $n>0; $n--) {
		for (;;) {
			$_ = shift @pipe;
			last unless defined $_;

			i_expect($name, $_, 0);
		}
	}
}

sub t_expect_flush($)
{
	my ($name) = @_;
	my $handle = $conns{$name};
	mdebug('t_expect_flush [%s]', $name);

	my $line;
	eval {
		local $SIG{'ALRM'} = sub { die; };
		alarm($set{'flush_timeout'});
		for (;;) {
			$line = <$handle>;
			last unless defined($line);

			mdebug('t_expect_flush from [%s] [%s]', $name, i_printable($line));
		}
		alarm(0);
	};

	@pipe = ();
}

sub t_pipe_flush()
{
	@pipe = ();
}

sub t_pipe_pop()
{
	return shift @pipe;
}

sub t_expect_any($)
{
	my ($name) = @_;
	my $handle = $conns{$name};
	mdebug('t_expect_any [%s]', $name);

	my $line;
	eval {
		local $SIG{'ALRM'} = sub { die "t_expect_any[$name] timeout!\n"; };
		alarm($set{'timeout'});
		for (;;) {
			$line = <$handle>;
			last unless defined($line);
		}
		alarm(0);
	};

	die $@ if ($@);
}

sub t_expect_closed($;$)
{
	my ($name, $timeout) = @_;
	my $handle = $conns{$name};
	mdebug('t_expect_closed [%s]', $name);

	$timeout = $set{'timeout'} unless defined($timeout);

	my $line;
	eval {
		local $SIG{'ALRM'} = sub { die "t_expect_closed[$name] timeout!\n"; };
		alarm($timeout);
		$line = <$handle>;
		alarm(0);
	};

	die $@ if ($@);

	if (defined($line)) {
		my $cstr = i_printable($line);
		die "t_expect_closed($name): got [$cstr]\n";
	}

	delete $conns{$name};
}

sub t_expect_nothing($;$)
{
	my ($name, $timeout) = @_;
	my $handle = $conns{$name};
	mdebug('t_expect_nothing [%s]', $name);

	$timeout = $set{'flush_timeout'} unless defined($timeout);

	my $line;
	eval {
		local $SIG{'ALRM'} = sub { die "OK\n"; };
		alarm($timeout);
		$line = <$handle>;
		alarm(0);
	};

	if ($@ ne "OK\n") {
		my $cstr = i_printable($line);
		die "t_expect_nothing($name): got [$cstr]\n";
	}
}


sub eicar_signature()
{
	return 'X5O!P%@AP[4\\PZX54(P^)' . '7CC)7}$EI' . 'CAR-STANDARD-A' . 'NTIVIRUS-TEST-FILE!$H+H*';
}

sub gtube_signature()
{
	return 'XJS*C4JDBQADN1.NSBN3*2ID' . 'NEN*GT' . 'UBE-STANDARD-ANTI-' . 'UBE-TEST-EMAIL*C.34X';
}

sub t_eicar_body()
{
	return (
		'Subject: eicar test message',
		'MIME-Version: 1.0', 
		'Content-Type: multipart/mixed; boundary="=-=-="',
		'',
		'--=-=-=',
		'Content-Type: application/octet-stream',
		'Content-Disposition: attachment; filename=eicar.gif',
		'Content-Description: EICAR test file',
		'',
		eicar_signature(),
		'--=-=-=--',
		'',
		'.');
}

sub t_gtube_body(;$)
{
	my $score = $_[0];
	$score = 10 unless defined($score);

	return (
		'Subject: gtube test message',
		'MIME-Version: 1.0', 
		'Content-Type: text/plain; charset=us-ascii',
		'Content-Transfer-Encoding: 7bit',
		"Score: $score",
		'',
		gtube_signature(),
		'',
		'.');
}

sub t_eicar_catch()
{
	t_smtp_one('DATA', '354 go ahead');
	t_println_push($cli, (
		'Subject: eicar test message',
		'MIME-Version: 1.0', 
		'Content-Type: multipart/mixed; boundary="=-=-="',
		'',
		'--=-=-=',
		'Content-Type: application/octet-stream',
		'Content-Disposition: attachment; filename=eicar.gif',
		'Content-Description: EICAR test file',
		'',
		eicar_signature(),
		'--=-=-=--',
		'',
	));
	t_println($cli, '.');

	t_expect_pop($srv);
	t_expect_closed($srv);

	t_expect_regex($cli, '^550 [a-zA-Z0-9]');
	t_println($cli, 'QUIT');
	t_expect_regex($cli, '^221 ');
	t_expect_closed($cli);

	t_debug_expect('CHILD_GONE');
}

sub t_gtube_catch()
{
	t_smtp_one('DATA', '354 go ahead');
	t_println_push($cli, (
		'Subject: gtube test message',
		'MIME-Version: 1.0', 
		'Content-Type: text/plain; charset=us-ascii',
		'Content-Transfer-Encoding: 7bit',
		'Score: 10',
		'',
		gtube_signature(),
		''
	));
	t_println($cli, '.');

	t_expect_pop($srv);
	t_expect_closed($srv);

	t_expect_regex($cli, '^550 [a-zA-Z]');
	t_println($cli, 'QUIT');
	t_expect_regex($cli, '^221 ');
	t_expect_closed($cli);

	t_debug_expect('CHILD_GONE');
}

sub t_eicar_pass()
{
	t_smtp_one('DATA', '354 go ahead');
	t_println_push($cli, t_eicar_body());
	t_expect_pop($srv);

	t_println($srv, '250 Spool OK');
	t_expect($cli, $prev);
}

sub t_gtube_pass()
{
	t_smtp_one('DATA', '354 go ahead');
	t_println_push($cli, t_gtube_body());
	t_expect_pop($srv);

	t_println($srv, '250 Spool OK');
	t_expect($cli, $prev);
}

#
# SMTP functions
#

sub t_change(;$$)
{
	$cli = shift || 'cli';
	$srv = shift || 'srv';
}

sub t_smtp_init(;$$;$)
{
	my ($_cli, $_srv, $srcip) = @_;

	if (defined($_cli)) {
		$cli = $_cli;
		$srv = $_srv;
	}

	mdebug('--- t_smtp_init(%s,%s)', defined($_cli) ? $_cli : '', defined($_srv) ? $_srv : '');
	t_connect($cli, $srcip);
	t_accept($srv);

	# mandatory - otherwise proxy pipeline queue gets out-of-order
	t_println($srv, '220 fake MTA says hello ESMTP');
	t_expect($cli, $prev);
}

sub t_smtp_helo(;$)
{
	my $host = shift || 'host.example.com';

	mdebug('--- t_smtp_helo()');
	t_println($cli, "HELO $host");
	t_expect($srv, $prev);
	t_println($srv, "250 Hello $host");
	t_expect($cli, $prev);
}

sub t_smtp_ehlo(@)
{
	my %flags = @_;

	my @options = ('fake MTA greets host.example.com');
	push @options, 'PIPELINING' unless defined($flags{'pipe'}) and $flags{'pipe'} == 0;
	push @options, 'STARTTLS' unless defined($flags{'tls'}) and $flags{'tls'} == 0;
	push @options, 'AUTH PLAIN LOGIN' if $flags{'auth'};
	push @options, 'CHUNKING' if $flags{'chunking'};

	my $c = scalar @options;
	@options = map { $c--; ($c) ? "250-$_" : "250 $_" } @options;

	mdebug('--- t_smtp_ehlo()');
	t_println($cli, 'EHLO host.example.com');
	t_expect($srv, $prev);
	t_println_push($srv, @options);
	t_expect_pop($cli);
}

sub t_smtp_auth()
{
	t_smtp_one('AUTH LOGIN abc', '235 Auth success');
}

sub t_smtp_auth_reject()
{
	t_smtp_one('AUTH LOGIN abc', '535 Auth success');
}

sub t_smtp_mail_rcpt(;$$)
{
	my ($mail_from, $rcpt_to) = @_;
	$mail_from = 'user@example.com' unless $mail_from;
	$rcpt_to = 'user@example.com' unless $rcpt_to;

	t_println_push($cli,
		"MAIL FROM: <$mail_from>",
		"RCPT TO: <$rcpt_to>"
	);
	t_expect_pop($srv);
	t_println_push($srv, '250 OK', '250 OK');
	t_expect_pop($cli);
}

sub t_smtp_data()
{
	t_println($cli, 'DATA');
	t_expect($srv, $prev);
	t_println($srv, '354 go ahead');
	t_expect($cli, $prev);
}

sub t_smtp_data_body(;$)
{
	my $body = shift || 'the one and only line';

	t_println_push($cli,
		'From: source@test.com',
		'To: source@test.com',
		''
	);
	t_expect_pop($srv);

	t_println_push($cli, split /\n/, $body);
	t_expect_pop($srv);
}

sub t_smtp_send(;$)
{
	my $body = shift;

	t_smtp_data();
	t_smtp_data_body($body);

	t_println_push($cli, '.');
	t_expect_pop($srv);
	
	t_println($srv, '250 Spool OK');
	t_expect($cli, $prev);
}

sub t_smtp_one($$)
{
	my ($verb, $response) = @_;

	t_println($cli, $verb);
	t_expect($srv, $prev);
	t_println($srv, $response);
	t_expect($cli, $prev);
}

sub t_smtp_quit()
{
	t_println($cli, 'QUIT');
	t_expect($srv, $prev);
	t_println($srv, '221 Bye bye');
	t_expect($cli, $prev);

	t_close($srv);
	t_expect_closed($cli);

	t_debug_expect('CHILD_GONE');
}

sub t_smtp_is_locked(;$;$)
{
	my $cli = shift || $cli;
	my $ip = shift || undef;

	t_connect($cli, $ip);
	t_expect_regex($cli, '^554 .*');
	t_expect_closed($cli);

	# no child process for host-locked
	# t_debug_expect('CHILD_GONE');
}

sub t_smtp_is_ratelimited(;$;$)
{
	my $cli = shift || $cli;
	my $ip = shift || undef;

	t_connect($cli, $ip);
	t_expect_regex($cli, '^554 .*');
	t_expect_closed($cli);

	t_debug_expect('CHILD_GONE');
}

sub i_read_defs()
{
	open(DEF, "$set{bin} -V|") || die "can't read defines: $!\n";
	while (defined($_=<DEF>)) {
		chomp;
		next unless /^ *(.*?) *: +(.*?) *$/o;
	
		$defs{$1} = $2;
	}
	close(DEF);
	#printf "%s => %s\n", $_, $defs{$_} foreach (sort keys %defs);
	
	open(DEF, "$set{bin} -t|") || die "can't read defines: $!\n";
	while (defined($_=<DEF>)) {
		chomp;
		next unless /^#/o;
		next unless /^ *([^ ]+) *(.*?) *$/o;
		my ($name, $val) = ($1, $2);
		next if $name =~ /:.*:/o;
	
		$conf{$name} = $val;
	}
	close(DEF);
	#printf "%s => %s\n", $_, $conf{$_} foreach (sort keys %conf);
}

sub i_init_conf()
{
	%initconf = %conf;
}

sub i_init_dirs()
{
	unless (-d $conf{'lock_path'}) {
		die "lock_path[$conf{lock_path}] is not a directory!\n" if (-e $conf{'lock_path'});
		mkdir $conf{'lock_path'} || die "can't mkdir lock_path[$conf{lock_path}]: $!\n";
	}
	
	unless (-d $conf{'spool_path'}) {
		die "spool_path[$conf{spool_path}] is not a directory!\n" if (-e $conf{'spool_path'});
		mkdir $conf{'spool_path'} || die "can't mkdir spool_path[$conf{spool_path}]: $!\n";
	}
	
	eval {
		my $testconn = IO::Socket::INET->new(Proto=>'tcp', Listen=>1, $reuse=>1,
			LocalAddr=>$set{'src_ip_alt'}, LocalPort=>$set{'mta_port'}+10);
	
		die unless defined($testconn);
		$testconn->close();
	};
	$set{'alt_ip_ok'} = ($@) ? 0 : 1;
	#printf "alt_ip: %s\n", $set{'alt_ip_ok'};
}

# signals received:
# USR1:	from proxy process, after spawn/reload
# USR2:	from av/spam emulator
# HUP:	from testing scripts

sub i_init_signals()
{
	$SIG{'__WARN__'} = sub { printf STDERR "\n--- WARNING: %s", $_[0]; };
#	$SIG{'__DIE__'} = sub { printf STDERR "\n--- DIE: %s\n%s\n--- END OF TRACE\n", $_[0], stack_trace(); die shift; };
	$SIG{'CHLD'} = 'IGNORE';
	$SIG{'HUP'} = 'IGNORE';
	$SIG{'USR1'} = 'IGNORE';
	$SIG{'USR2'} = sub { die; };
	#$SIG{'TERM'} = sub { die };
}

sub i_time2human($)
{
	use integer;
	my $time = shift;
	my $mins = $time / 60;
	$time %= 60;
	return sprintf "%02s:%02s", $mins, $time;
}


my %tests;

sub register(&)
{
	my ($func) = @_;
	$tests{$test_name} = $func;
	return 1;
}


sub uniq(@)
{
	$_{$_}++ foreach @_;
	return keys %_;
}

sub i_load(@)
{
	my @tests = @_;
	printf "loading %s tests...\n", scalar @tests;
	foreach $test_name (sort uniq @tests) {
		eval {
			require "$test_name";
		};
		if ($@) {
			chomp $@;
			printf "Error loading test %s: %s\n", $test_name, $@;
		}
	};

	print '=' x HR,"\n";
	print "All tests developed on Debian GNU/Linux - may fail on other platforms\n";
	print '=' x HR,"\n";
	printf "%16s tests found: %s, registered: %s\n", '', scalar @tests, scalar keys %tests;
	print '=' x HR,"\n";
}


sub i_run()
{
	#
	# run tests

	my @tests = @_;

	i_load(@tests);

	my ($passed, $failed, $warned, $notrun, @results);
	$passed = $failed = $warned = $notrun = 0;
	
	$| = 1;
	open(STDERR, '>'.$set{log}) || die "can't redirect STDERR to $set{log}: $!\n";
	$| = 1;
	print STDERR "*** $0 pid $$\n";
	print STDERR "*** ".scalar localtime()."\n\n\n";
	unlink($conf{'pidfile'});

	eval {
		i_spawn_clamd_emu();
		i_spawn_spamd_emu();
		i_save_config();
		t_spawn_proxy();
	
		foreach $test_name (@tests) {
			i_progress('');
			print STDERR "\n\n--- $test_name ---\n";
			$set{'start'} = time();
	
			# cleanup
			i_lock_cleanup();
	
			t_listen();
			t_init_config();


			my ($duration, $result);
			if (defined($set{'skip'}) and ($test_name =~ $set{'skip'})) {
				$notrun++;
				$result = 'skip';
				i_progress($result);
			} else {
				eval {
					$prev = undef;
					@pipe = ();
					$cli = 'cli';
					$srv = 'srv';
					$reloads = 0;

					#require "$test_name";
					if (ref($tests{$test_name}) eq 'CODE') {
						$tests{$test_name}->();
					} else {
						die "test subroutine for $test_name is undefined or non-code!\n";
					}
					die "sockets left: [".join(';', sort grep { $_ ne '*' } keys %conns)."]\n" if 1 < scalar keys %conns;

					my @locks = i_list_locks();
					die "locks left: [".join(';', sort @locks)."]\n" if @locks;
				};
				
				# test script must do reload by itself
				printf "WARNING: no t_reload detected!\n" unless $reloads || $@;
				$duration = time() - $set{'start'};
				printf STDERR "--- DURATION: %s\n", $duration;

				if ($@ =~ m%^TODO\n%io) {
					$notrun++;
					$result = 'todo';
					print STDERR "\n--- $test_name: TODO\n";
					i_progress($result);
				} elsif ($@ =~ m%^N/A: (.*)\n%io) {
					$notrun++;
					$result = "n/a:$1";
					print STDERR "\n--- $test_name: N/A: $1\n";
					i_progress("n/a");
				} elsif ($@ =~ m%^WARN: (.*)\n%io) {
					$warned++;
					$result = "warn:$1";
					print STDERR "\n--- $test_name: WARNING: $1\n";
					i_progress('warn');
				} elsif ($@ =~ m%^LONG\n%io) {
					$notrun++;
					$result = 'long';
					print STDERR "\n--- $test_name: LONG\n";
					i_progress($result);
				} elsif ($@) {
					$failed++;
					chomp $@;
					$result = 'FAILED';
					print STDERR "\n--- $test_name: FAILED: $@\n";
					i_progress($result);
				} else {
					$passed++;
					$result = 'pass';
					print STDERR "\n--- $test_name: PASSED\n";
					i_progress($result);
				}
			}

			push @results, {name=>$test_name, result=>$result, duration=>$duration};
			i_progress_done($@);
			printf "%s\n",  ' 'x16;
	
			t_close_all();
		}
		
		#
		# quit
	
		t_close_all();
		i_kill_clamd_emu();
		i_kill_spamd_emu();
		eval {
			t_signal(15);
			t_debug_expect('QUIT');
			t_wait();
		};
	
		printf "%s\n", '=' x HR;
		printf "  pass:%-2s | warn:%-2s | fail:%-2s | skip:%-2s | total:%-2s\n",
			$passed, $warned, $failed, $notrun, scalar @tests;
		printf "%s\n", '=' x HR;

		open(SUMMARY, '>'.$set{'summary'}) || die "can't write summary to $set{summary}: $!\n";
		printf SUMMARY "%s\n", '=' x HR;
		printf SUMMARY "%18s ver %s, %s\n", 'SUMMARY:', $defs{'version'}, scalar localtime();
		printf SUMMARY "%s\n", '=' x HR;
		printf SUMMARY "%-32s %-6s %s\n", $_->{'name'}, i_time2human($_->{'duration'}), $_->{'result'} foreach (@results);
		printf SUMMARY "%s\n", '=' x HR;
		printf SUMMARY "  pass:%-2s | warn:%-2s | fail:%-2s | skip:%-2s | total:%-2s\n",
			$passed, $warned, $failed, $notrun, scalar @tests;
		printf SUMMARY "%s\n", '=' x HR;
		close(SUMMARY);
	};
	
	if ($@) {
		print "! FAIL: $@\n";
		t_signal(15);
		t_close_all();
		i_kill_clamd_emu();
		i_kill_spamd_emu();
	
		eval {
			t_wait();
		};
		if ($@) {
			t_signal(9);
		}
		exit(1);
	}

	i_kill_clamd_emu();
	i_kill_spamd_emu();
	
	exit($failed != 0);
}



1;
