#
# check if BDAT is sane
# BDAT is currently not functional, do not enable!
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	die "N/A: no BDAT support\n" if ($defs{'FILTER_CHUNKING'} || 'yes') eq 'yes';
#	die "TODO\n";

	my $body = "From: a\@example.com\r\nTo: a\@example.com\r\nSubject: BDAT test\r\n\r\nthis is message body\r\n";
	my $len = length($body);

	t_reload();
	t_smtp_init();
	t_smtp_ehlo(chunking=>1);
	t_smtp_mail_rcpt();

	# BDAT x LAST => BDAT x; BDAT 0 LAST
	t_print('cli', "BDAT $len LAST\r\n");
	t_expect('srv', "BDAT $len\r\n");
	# send message
	t_print('cli', $body);
	t_expect('srv', $body);
	# BDAT magic
	t_print('srv', '250 OK');	# gets stolen by proxy
	t_expect('srv', 'BDAT 0 LAST');	# injected by proxy
	t_print('srv', '250 Message OK');
	t_expect('cli', '250 Message OK');

	t_smtp_quit();
});

# : vim: syntax=perl :

__END__

RFC3030:

4.1 Simple Chunking

   The following simple dialogue illustrates the use of the large
   message extension to send a short pseudo-RFC 822 message to one
   recipient using the CHUNKING extension:

   R: <wait for connection on TCP port 25>
   S: <open connection to server>
   R: 220 cnri.reston.va.us SMTP service ready
   S: EHLO ymir.claremont.edu
   R: 250-cnri.reston.va.us says hello
   R: 250 CHUNKING
   S: MAIL FROM:<Sam@Random.com>
   R: 250 <Sam@Random.com> Sender ok
   S: RCPT TO:<Susan@Random.com>
   R: 250 <Susan@random.com> Recipient ok
   S: BDAT 86 LAST
   S: To: Susan@random.com<CR><LF>
   S: From: Sam@random.com<CR><LF>
   S: Subject: This is a bodyless test message<CR><LF>
   R: 250 Message OK, 86 octets received
   S: QUIT
   R: 221 Goodbye

4.2 Pipelining BINARYMIME

   The following dialogue illustrates the use of the large message
   extension to send a BINARYMIME object to two recipients using the
   CHUNKING and PIPELINING extensions:

   R: <wait for connection on TCP port
   S: <open connection to server>
   R: 220 cnri.reston.va.us SMTP service ready
   S: EHLO ymir.claremont.edu
   R: 250-cnri.reston.va.us says hello
   R: 250-PIPELINING
   R: 250-BINARYMIME
   R: 250 CHUNKING
   S: MAIL FROM:<ned@ymir.claremont.edu> BODY=BINARYMIME
   S: RCPT TO:<gvaudre@cnri.reston.va.us>
   S: RCPT TO:<jstewart@cnri.reston.va.us>
   R: 250 <ned@ymir.claremont.edu>... Sender and BINARYMIME ok
   R: 250 <gvaudre@cnri.reston.va.us>... Recipient ok
   R: 250 <jstewart@cnri.reston.va.us>... Recipient ok
   S: BDAT 100000
   S: (First 10000 octets of canonical MIME message data)
   S: BDAT 324
   S: (Remaining 324 octets of canonical MIME message data)
   S: BDAT 0 LAST
   R: 250 100000 octets received
   R: 250 324 octets received
   R: 250 Message OK, 100324 octets received
   S: QUIT
   R: 221 Goodbye

