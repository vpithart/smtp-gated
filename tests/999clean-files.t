#
# check if msg/ and lock/ are empty
#

use strict;
use vars qw(%set %conf %defs $prev);

register(sub {
	t_reload();

	sub empty_dir($)
	{
		my $dir = shift;

		opendir(D, $dir) || die "can't open dir [$dir]: $!\n";
		my @files = grep { ! /^\.+$/ } readdir(D);
		closedir(D);

		return scalar @files == 0;
	}

	die "spool directory [$conf{spool_path}] not empty!\n" unless empty_dir($conf{'spool_path'});
	die "lock directory [$conf{lock_path}] not empty!\n" unless empty_dir($conf{'lock_path'});
});

# : vim: set syntax=perl :
