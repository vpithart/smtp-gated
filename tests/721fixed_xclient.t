#
# check fixed+xclient mode
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	$conf{'mode'} = 'fixed+xclient';
	t_progress_init(2);
	t_reload();

	# --- pass 1: simple
	t_progress_next();
	t_connect($cli);
	t_accept($srv);

	t_println('srv', '220 test.example.com ESMTP fake-mta');
	t_expect_regex('srv', '^EHLO ');	# $conf{'proxy_name'};
	t_println('srv',
		'250-PIPELINING',
		'250 XCLIENT NAME ADDR PROTO HELO',
	);
	t_expect_regex('srv', '^XCLIENT ADDR=(.*) NAME=(.*)$');
	t_println('srv', '220 test.example.com ESMTP fake-mta');
	t_expect('cli', $prev);
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();


	# --- pass 2: fdgetline buffering test
	t_progress_next();
	t_connect($cli);
	t_accept($srv);

	t_println('srv', '220 test.example.com ESMTP fake-mta');
	t_expect_regex('srv', '^EHLO ');	# $conf{'proxy_name'};
	t_println('srv', "250-SIZE=1000000\r\n250-PIPELINING\r\n250 XCLIENT NAME ADDR PROTO HELO");
	t_expect_regex('srv', '^XCLIENT ADDR=(.*) NAME=(.*)$');
	t_println('srv', '220 test.example.com ESMTP fake-mta');
	t_expect('cli', $prev);
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# check fdgetline (as one buffer):
	# 250-SIZE=1000000\r\n250-PIPELINING\r\n250 XCLIENT NAME ADDR PROTO HELO\r\n
});

# : vim: syntax=perl :

__END__

220 server.example.com ESMTP Postfix
EHLO client.example.com
250-server.example.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-XCLIENT NAME ADDR PROTO HELO
250 8BITMIME
XCLIENT NAME=spike.porcupine.org ADDR=168.100.189.2
220 server.example.com ESMTP Postfix
EHLO spike.porcupine.org
250-server.example.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-XCLIENT NAME ADDR PROTO HELO
250 8BITMIME
MAIL FROM:<wietse@porcupine.org>
250 Ok
RCPT TO:<user@example.com>
250 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
[...]
.
250 Ok: queued as 763402AAE6
QUIT
221 Bye

