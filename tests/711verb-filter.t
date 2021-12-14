#
# check if unsupported SMTP extensions are filtered properly
#

use strict;
use vars qw(%set %conf %defs $prev);


register(sub {
	if ($defs{'FILTER_CHUNKING'} ne 'yes') {
		t_debug('FILTER_CHUNKING not defined during compilation - test skipped');
		die "N/A: FILTER_CHUNKING not defined\n"
	}

	t_reload();

	t_connect('cli');
	t_accept('srv');

	t_println('srv', '220 fake MTA says hello (so be prepared)');
	t_expect('cli', $prev);

	t_println('cli', 'EHLO fake.MUA');
	t_expect('srv', $prev);
	t_println_push('srv',
		'250-fake MTA greets fake.MUA (be still prepared)',
		'250-SIZE 10000000',
		'250-X-RCPTLIMIT 10000',
		'250-PIPELINING',
		'250-ENHANCEDSTATUSCODES',
		'250-DSN',
		'250-AUTH=LOGIN',
		'250-AUTH LOGIN',
		'250-STARTTLS',
		'250-8BITMIME',
		'250-HELP'
	);
	t_expect_pop('cli');

	#
	# these should be filtered
	#

	t_println('srv', '250-BINARYMIME');
	t_println('srv', '250-CHUNKING');
	t_println('srv', '250 XEXCH50');

	t_expect('cli', "250-BIN*RYMIME\r\n");
	t_expect('cli', "250-CHU*KING\r\n");
	t_expect('cli', "250 XEX*H50\r\n");

	t_smtp_mail_rcpt();
	t_smtp_send();
	t_smtp_quit();
});

# : vim: syntax=perl :
