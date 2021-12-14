#!/usr/bin/perl -w
#@PERL@ -w

use strict;
use Socket;
use IO::Handle;
use POSIX qw(getcwd);
use Getopt::Long;
require 'common.pm';

use constant HR => 70;

#use Cwd;

#
# vars

our (%set, %conf, @local_ips);

#
# test configuration

sub help()
{
	print "$0: [--help | -h] [--leak | -K] [--long | -l] [--gdb | -g] [--skip REGEX] [test1 test2 ...]\n";
	exit 0;
}

GetOptions(
	"help|h" => \&help,
	"leak|K" => \$set{'leak'},
	"gdb|g" => \$set{'gdb'},
	"long|l+" => \$set{'long'},
	"skip=s" => \$set{'skip'},
) || help();


my @tests = @ARGV;
#while (defined($_ = shift @ARGV)) {
##	printf "ARG: %s\n", defined($_) ? $_ : 'undef';
#	if (/^--long$/) {
#		$set{'long'}++;
#	} elsif (/^--leak$/) {
#		$set{'leak'}++;
#	} elsif (/^--gdb$/) {
#		$set{'gdb'}++;
#	} elsif (/^--skip$/) {
#		$set{'skip'} = shift;
#	} elsif (/^--tests$/) {
#		@tests = @ARGV;
#		last;
#	} elsif (/^-h$|^--help$/) {
#	} else {
#		printf "Invalid parameters: %s\n", join(' ', @ARGV);
#		exit 3;
#	}
#}

$set{'debug'} = 2;
$set{'path'} = getcwd();
$set{'bin'} = "$set{path}/../src/smtp-gated";
$set{'wrapper'} = $set{'leak'} ? "valgrind -v --log-file=log/valgrind-%p.log --leak-check=full" : ($set{'gdb'} ? "gdb --batch --command debug.gdb --args " : "");
i_read_defs();

$set{'path_log'} = "$set{path}/log";
$set{'log'} = "$set{path_log}/test.log";
$set{'summary'} = "$set{path_log}/summary.log";

$set{'src_ip'} = '127.0.0.1';
$set{'src_ip_alt'} = '127.0.0.2';
$set{'test_port'} = 2110;

# 0.0.0.0 for testing SPF
$set{'ip_mta'} = '0.0.0.0';
$set{'mta_port'} = $set{'test_port'} + 1;
$set{'ip_clamd'} = $set{'ip_mta'};
$set{'port_clamd'} = $set{'test_port'} + 2;
$set{'ip_spamd'} = $set{'ip_mta'};
$set{'port_spamd'} = $set{'test_port'} + 3;

$set{'timeout'} = $set{'gdb'} ? 20 : 10;
$set{'flush_timeout'} = 1;
$set{'process_timeout'} = ($set{'leak'} || $set{'gdb'}) ? 15 : 3;
$set{'close_delay'} = 0.0;

# ../src/smtp-gated.h:
#define FORE_LOG_TRAFFIC	0x0001
#define FORE_DEBUG_STAGE	0x0002
#define FORE_SINGLE		0x0004

# my ($debug_client);
# socketpair($debug_socket, $debug_client, AF_UNIX, SOCK_STREAM, PF_UNSPEC);
# $set{'args'} = sprintf "-D 0x03 -DS %s", $debug_client->fileno;

$set{'args'} = "-D 0x03";
$set{'conf'} = "$set{path}/log/test.conf";
#$set{'redir'} = "1>$set{log} 2>$set{log}";
$set{'redir'} = '';


#
# daemon default configuration

$conf{'limit_core_size'} = 0;
$conf{'limit_virt_size'} = 0;
$conf{'limit_data_size'} = 0;
$conf{'limit_fsize'} = 0;

$conf{'pidfile'} = "$set{path}/test.pid";
$conf{'statefile'} = "$set{path_log}/state";
$conf{'spool_path'} = "$set{path}/msg";
$conf{'lock_path'} = "$set{path}/lock";
$conf{'ratelimit_path'} = "$set{path}/ratelimit";
$conf{'ratelimit_generation'} = 0;
$conf{'proxy_name'} = 'proxy.auto.test';
#$conf{'bind_address'} = $set{'ip_mta'};
# must be 0.0.0.0 for SPF-testing (different addresses)
$conf{'bind_address'} = '0.0.0.0';
$conf{'port'} = $set{'mta_port'} + 10;
#$conf{'fixed_server'} = $set{'ip_mta'};
$conf{'fixed_server'} = '127.0.0.1';
$conf{'fixed_server_port'} = $set{'mta_port'};
$conf{'mode'} = 'fixed';
$conf{'antivirus_path'} = "$set{ip_clamd}:$set{port_clamd}";
$conf{'antispam_path'} = "$set{ip_spamd}:$set{port_spamd}";
$conf{'antivirus_type'} = 'clamd';
$conf{'antispam_type'} = 'spamassassin';
$conf{'lock_on'} = 'never';
$conf{'auth_skip'} = 'none';
$conf{'log_level'} = 7;
$conf{'max_connections'} = 32;
$conf{'max_per_host'} = 4;
$conf{'max_load'} = 100;
$conf{'spam_max_load'} = 100;
$conf{'ignore_errors'} = 0;
$conf{'spam_max_size'} = 0;
$conf{'nat_header_type'} = 'none';

# must be set high for PID hashing test
#$conf{'max_connections'} = 32000;
#$conf{'max_connections'} = 1001;

$set{'lock'} = "$conf{lock_path}/$set{src_ip}";

mkdir $_ foreach map { $conf{$_} || $set{$_} } qw(path_log spool_path lock_path ratelimit_path);

#
# setup

i_init_conf();
i_init_dirs();
i_init_signals();

# find IP to use here
if (open(IP, '/sbin/ip addr |') || open(IP, '/bin/ip addr |')) {
	@local_ips = map { m%inet ([^ ]+?)/[0-9]+ %o } grep { m%inet %o and !m%inet 127%o } <IP>;
	close(IP);
}

#
# find tests

if (@tests == 0) {
	opendir(DIR, ".") || die "can't open '.' directory: $!\n";
	@tests = sort grep { /^[0-9]\d{2}.*\.t$/o } readdir(DIR);
	closedir(DIR);
}


eval {
	require BSD::Resource;
	import BSD::Resource;
	eval "setrlimit(RLIMIT_CORE, 50000, 50000)";
};

i_run(@tests);


__END__

0xx: startup
1xx: scanner, dnsbl, spf
2xx:
3xx:
4xx:
5xx: script, locking
6xx: timeout, limit
7xx: protocol, filtering, overflow
8xx: stress testing
9xx: cleanup


