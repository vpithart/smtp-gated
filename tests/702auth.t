#
# check if auth_require works
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_progress_init(9);

	sub data_auth_reject()
	{
		t_println($cli, 'DATA');
	#	t_pipe_pop();
		t_expect_regex($cli, '^530 ');
	#	t_expect_regex($srv, "^NOOP\r\n");
	}


	# "no" => pass
	$conf{'auth_require'} = 'no';
	t_progress_next();
	t_reload();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_auth();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_auth_reject();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# "yes", not advertised => pass
	t_progress_next();
	$conf{'auth_require'} = 'ifsupported';
	t_reload();
	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	t_smtp_init();
	t_smtp_ehlo();
	t_smtp_auth();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# "yes", advertised, not authorized/auth failed => reject
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_mail_rcpt();
	data_auth_reject();
	t_smtp_quit();

	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_auth_reject();
	t_smtp_mail_rcpt();
	data_auth_reject();
	t_smtp_quit();

	# "yes", advertised, auth ok => pass
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_auth();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# "always", not advertised/failed => reject
	t_progress_next();
	$conf{'auth_require'} = 'mandatory';
	t_reload();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_auth_reject();
	t_smtp_mail_rcpt();
	data_auth_reject();
	t_smtp_quit();

	# "always", advertised, not authorized => reject
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_mail_rcpt();
	data_auth_reject();
	t_smtp_quit();

	# "always", advertised, authorized => pass
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_auth();
	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();

	# auth initial-response
	# auth challenge + response
});

#	S: 220 smtp.example.com ESMTP server ready
#	C: EHLO jgm.example.com
#	S: 250-smtp.example.com
#	S: 250 AUTH CRAM-MD5 DIGEST-MD5
#	C: AUTH FOOBAR
#	S: 504 Unrecognized authentication type.
#	C: AUTH CRAM-MD5
#	S: 334
#	PENCeUxFREJoU0NnbmhNWitOMjNGNndAZWx3b29kLmlubm9zb2Z0LmNvbT4=
#	C: ZnJlZCA5ZTk1YWVlMDljNDBhZjJiODRhMGMyYjNiYmFlNzg2ZQ==
#	S: 235 Authentication successful.

# : vim: syntax=perl :

