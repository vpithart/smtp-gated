#
# check if auth_skip works
#

use strict;
use vars qw(%set %conf %defs);

register(sub {
	my @scenarios = ('none', 'antivir', 'antispam', 'antivir,antispam');

	t_progress_init(1+scalar @scenarios);

	$conf{'spam_max_size'} = 10000;
	$conf{'spam_threshold'} = 5;
	$conf{'lock_on'} = 'spam';
	t_reload();

	# catch virus&spam
	foreach my $auth_skip (@scenarios) {
		$conf{'auth_skip'} = $auth_skip;
		t_progress_next();
		t_reload();
		t_debug("auth_skip: %s\n", $auth_skip);

		# no malware, just pass
		t_smtp_init();
		t_smtp_ehlo(auth => 1);
		t_smtp_mail_rcpt();
		t_smtp_send();
		t_smtp_quit();

		# no auth, takeover
		t_debug("eicar/noauth\n");
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_eicar_catch();

		# no auth, takeover
		t_debug("gtube/noauth\n");
		t_smtp_init();
		t_smtp_ehlo();
		t_smtp_mail_rcpt();
		t_gtube_catch();
		t_lock_remove();

		# no auth, takeover
		t_debug("eicar/noauth\n");
		t_smtp_init();
		t_smtp_ehlo(auth => 1);
		t_smtp_mail_rcpt();
		t_eicar_catch();

		# no auth, takeover
		t_debug("gtube/noauth\n");
		t_smtp_init();
		t_smtp_ehlo(auth => 1);
		t_smtp_mail_rcpt();
		t_gtube_catch();
		t_lock_remove();

		# auth
		t_debug("eicar/auth\n");
		t_smtp_init();
		t_smtp_ehlo(auth => 1);
		t_smtp_auth();
		t_smtp_mail_rcpt();
		if ($auth_skip =~ m%antivir%o) {
			t_eicar_pass();
			t_smtp_quit();
		} else {
			t_eicar_catch();
		}

		# auth
		t_debug("gtube/auth\n");
		t_smtp_init();
		t_smtp_ehlo(auth => 1);
		t_smtp_auth();
		t_smtp_mail_rcpt();
		if ($auth_skip =~ m%antispam%o) {
			t_gtube_pass();
			t_smtp_quit();
		} else {
			t_gtube_catch();
			t_lock_remove();
		}
	}

	$conf{'auth_skip'} = 'direct';
	t_reload();
	t_progress_next();
	t_smtp_init();
	t_smtp_ehlo(auth => 1);
	t_smtp_auth();
	t_smtp_mail_rcpt();
	t_eicar_pass();
	t_smtp_one('RSET', '250 OK');
	t_smtp_mail_rcpt();
	t_gtube_pass();
	t_smtp_quit();
});

# : vim: syntax=perl :
