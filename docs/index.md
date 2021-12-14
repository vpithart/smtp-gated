### Download
[smtp-gated-1.4.21.tar.gz](./smtp-gated-1.4.21.tar.gz)

### Change Log
version 1.4.21 (2021-12-14)
  - Fixed to compile with modern gcc 8.x on Debian 10/11

version 1.4.20.0 (2013.02.26)
  - FIXME auth_skip direct: should flush buffers
  - new value for auth_skip: direct
  - change @example.com in tests as they have started to use SPF records :)
  - added earlytalker count in stats
  - added forbid_starttls
  - updated header dependencies for detection and use of TPROXY

version 1.4.18.8 (2011.12.04)
  - FIXME: experimental ratelimit support (options: ratelimit_*); to be changed
  - regex-match debugging logs
  - setting proxy_name to "*" (asterisk, without quotes) uses
	system hostname&domainname (from now on by default)
  - fixed without USE_NAT_TPROXY
  - SOL_IP changed to IPPROTO_IP to be more portable
  - clarified BUG and child crash counters in state file
  - conditional mode: "tproxy,netfilter" (untested)
  - introduced PID hashing for high max_connections values (experimental)
  - introduced host hashing for high max_connections values (experimental)
  - fixed possible crash when daemon is reloaded after pipeline_size change
  - lock_duration exported to action_script environment
  - removed bug in untaint() usage
  - fixed FOUND environment variable for action scripts on REGEX matches
  - updated contrib/debian.init to conform LSB Dependency Boot
  - raised default values for limit_* configuration options
  - added HELO environment variable to action script
  - fixed doc installation (does not install *.html as man-h section)
  - client_callback() body split into multiple functions
  - simple earlytalker: does not delay the MTA greeting but reacts on
	MUA commands before the greeting
  - fixed conffile.c getline usage for systems not having getline()

version 1.4.17 (2010.08.29)
  - upgrade to TPROXY4, verified on Linux kernel 2.6.32
  - many TPROXY related fixes making it finally usable (thx to Tamer Mohamed)
  - no need to use getsockopt(SO_ORIGINAL_DST) for tproxy, so removed
  - new value for spool_leave_on: always

version 1.4.16.3 (2010.02.12)
  - new test cases for spf
  - new example configurations in contrib/
  - added last !BUG! date in statefile
  - test case for !BUG! (tests/997bug.t)
  - ChangeLog translation to English

version 1.4.16.2 (2009.01.06)
  - stats counters changed from int to unsigned int (thx to Tomasz Lemiech)
  - removed !BUG! when no HELO/EHLO and SPF enabled (thx to Slawek Fydryk)
  - added !BUG! counter

1.4.16.1
  - fixed libspf2 detection under freebsd
  - fixed netfilter detection under linux (kernel headers changed?)

version 1.4.16 (2008.09.07)
  - just version change from 1.4.16-rc2

1.4.16-rc2 :
  - changed "spf" option values: from "source" to "incoming"
  - added "fixed" for spf option, and spf_fixed_ip (for proxy behind NAT)
  - 64bit architectures support

version 1.4.16-rc1 (2008.01.24)
  - fixed compilation error under OpenBSD and NetBSD
  - fixed bug in auth_require causing pipeline desynchronization
  - name change of value for nat_header_type and auth_require
  - added size_limit option
  - added auth_skip option
  - (second) check of lock just before accepting message body
  - IPFilter<4000027 support (stolen from squid-cache.org)
  - DNSBL support (options: dnsbl)
  - XCLIENT support (options: mode fixed+xclient)
  - SPF support using libspf2 (options: spf, spf_log_only)
  - regex support using libpcre (options: regex_*, lock_on, auth_skip)
  - option name change: from source_addr to outgoing_addr
  - BROKEN preliminary DSPAM support using (libdspam)

version 1.4.15.1 (2006.12.11)
  - bug fix of statefile, shame to speak of the details :)
	print "I will never ever do any changes just before release\n"x1000

version 1.4.15 (2006.12.11)
  - fixed possible SIGSEGV
  - *BSD/pf support
  - *BSD/IPFilter support (patch by Bartosz Kuzma)
  - code cleanup
  - mksd works again
  - fixed bug of spam_max_load
  - fixed daemon dying on ECONNABORTED and ECONNRESET on FreeBSD
	("accept error: Software caused connection abort")
  - new mode: remote-udp (uses proxy-helper)
  - statefile now has flags
  - new option: statefile_type
  - options name change: from dumpfile* to statefile*
  - logging short stats before daemon exits
  - new command-line option: -C, showing effecting value for option
  - new command-line option: -K, kills background daemon
  - logging of local socket name for new connections

version 1.4.14-rc1 (2006.05.11)
  - big change of configuration options set
  - log_facility values limited to useful only
  - proxy version added to dumpfile
  - changes to "enum" type options handling
  - default spool file permissions changed to 0660
  - memory leak fixed, when MAIL FROM was not logged
  - big fat warning if proxy is running as root (this *will not* work)
  - new option: auth_require
  - "no-auth" counter added to statefile
  - "--enable-chunking" configure option is not tested and for 99%
    does not work. THIS IS NOT INTENDED FOR PRODUCTION USE!

version 1.4.12-rc9 (2005.12.02)
  - new option: log_facility
  - log_level and log_facility now accepts text values,
    possible values shown by "smtp-gated -T"
  - white-space deletion at the end of all option values
  - default pipeline_size changed from 64 to 128 entries
  - pipeline dump if overflowed
  - new option: dumpfile_perm, set permissions for dump file
  - fixed compilation on Solaris

version 1.4.12-rc8 (2005.10.27)
  - new tests
  - for "SPAM:" log entires: "result=..." changed to "score=..."
  - max_per_*_lock: locks if limit is reached
  - action_script: new FOUND values: "MAX_HOST", "MAX_IDENT"

version 1.4.12-rc7 (2005.09.25)
  - fixed ENHANCEDSTATUSCODES conformance for intercepted sessions
  - new tests
  - spam_max_size, scan_max_size changed types from int to unsigned int
  - documentation fixed
  - added PROXY_NAME to action_script environment
  - fixed FOUND environment variable for action_script

version 1.4.12-rc6 (2005.09.14)
  - new option: action_script
  - now lock works also for spam

version  1.4.12-rc5
  - child PIDs moved from shared memory to main process
  - SIGTERM/SIGQUIT now breaks service loop (child-processes)
  - fixed FreeBSD/ipfw detection
  - changed X-NAT-Received header format
  - option name change: from nat_header to nat_header_type
  - new options: nat_header, spool_header, pipeline_size
  - common log format ("src=" or "dst=" instead of "host=")
  - gcc4: fixed struct init in src/vars.h

version 1.4.12-rc4
  - remove spool file if pipeline is overflown (spool shall be empty anyway)
  - add \n at the end of lockfile

version 1.4.12-rc3 (2005.03.15)
  - removed memory leak at start()

version 1.4.12-rc2 (2005.03.14)
  - test-suite included in distribution

1.4.12-rc1 :
  - nat_header=2: wlacza prosty naglowek, "HEADER: ip_zrodlowe"
  - TCP sockets support for spamd_path and clamd_path
  - email_length: e-mail logging length limit (before md5), moved to runtime
  - fixed potential (but unlike) buffer overflow in printf for glibc >= 2.1
  - filtering of BINARYMIME and XEXCH50 extensions
  - atomic dump file write (rename)
  - added .spec for RPM
  - support for NAT on FreeBSD ipfw and compatible
  - added license on all files
  - moved to GNU autotools

version 1.4.11-2 (2005.02.23)
  - fixed compilation on (older?) versions of gcc
    ("warning: unnamed struct/union that defines no instances")

version 1.4.11 (2005.02.22)
  - locale updated on SIGHUP
  - fixed timeout handling and logging
  - critical fix in response()
  - fixed bug in configuration parsing for BOOL options
  - fixed base64 (last character)

version 1.4.10
  - limited length of HELO/EHLO in logs
  - spam_block: blocks spam
  - added option to log emails as base64+md5
  - log_mail_from and log_rcpt_to changed to bitmasks
  - fixed timeout handling
  - statistics counter for TLS connections
  - changes to config loading
  - config directives moved to setup.h
  - some code cleanup and split
  - option to change locale for system errors
  - manuals have arised :) smtp-gated(8) and smtp-gated.conf(5)

version 1.4.9
  - ENHANCEDSTATUSCODES support in proxy generated messages
  - some declarations changed fro signed to unsigned int
  - welcome/error SMTP code of proxy changed to 554
  - fixed possible shared memory leak

version 1.4.8
  - closing stdin/stdout/stderr on background
  - changed workdir to spool_patch for background
  - new option: chroot_path (all paths get relative to this!)
  - new command-line options: -s, -S, -r
  - get rid of ECONNRESET errors in getline
  - ignore SIGPIPE signal
  - new option: log_rcpt_to=1 => log accepted only, >1 => log all
  - new option: log_helo, log of HELO/EHLO
  - fixed DATA handling and potential pipeline desynchronization
  - new statistics: virus/spam/reject count
  - SIGTERM: close listening socket and wait for existing sesions to finish
  - some messages changed
  - fixed lockfile name creation using ident
  - updated init scripts for Debian and RedHat

version 1.4.7
  - spool name removed from logs
  - added X-Spool-Info at the beginning of spool
  - some log messages changed
  - log of recipients count for each session
  - MAIL FROM, RCPT TO are logged two in one message if possible
  - possibility to translate messages to polish (Makefile: -DPOLISH)

version 1.4.6 (2005.02.10)
  - virus named added to lockfile
  - changed permissions of PID file (macro)
  - Makefile strips proxy on upgrade
  - skip antispam if 1-minute loadavg is above spam_max_load

version 1.4.5 (2005.02.09)
  - show session traffic in dump file
  - log time and ident for direct proxy (TLS sessions)
  - accept no empty line at the end of config
  - fixed log_level handling
  - log of MAIL FROM and RCPT TO
  - PID file created after UID/GID change
  - logging of ident lookup if it's invalid
  - some code cleanup

version 1.4.4 (2005.02.06)
  - lock infected hosts (lock_path, lock_duration)
  - lockfile on UID=0 treated as "do not lock"
  - new option: log_level
  - log transaction count for each session
  - foreground moved from config to command-line
  - command-line change from "-c" to "-t" and "-T"
    (you need to finish upgrade manually!)
  - some code cleanup

version 1.4.3
  - remove spool and ignore error on spooling
  - cleanup of code, structures and names
  - timeout for connect() to SMTP server and ident service
  - state file: start date, restart date, uptime
  - SIGCHLD handling moved to main loop
  - messages are sent to stderr if running foreground
  - BDAT (theoretically) handled by direct_proxy like TLS
    (this means without any scanning)

version 1.4.2
  - preliminary support for BDAT (non-working)

version 1.4.1a
  - added EINTR handling for wait3()

version 1.4.1
  - added connections limit per ident
  - option name change: max_procs to max_connections, load_max to max_load
  - new options: priority, load_max
  - SIGUSR1: dump process state to dumpfile
  - fixed buffer overflow in spamscan()

version 1.3.15
  - option name change: timeout_connection to timeout_idle
  - some timeout have now new default values
  - accept "DATA [...]"
  - spamassassin support
    http://old.spamassassin.org/full/2.6x/dist/spamd/README.spamd
  - new option: use_netfilter
  - log client connection time
  - limit for connection count/per host: max_procs/max_per_host

version 1.3.14
  - new option: timeout_connection
  - config shown from config_options
  - default values in config_options
  - changed header X-NAT-Path to X-NAT-Received
  - new option: abuse (email added to headers)
  - block moved to inject_nat_header()
  - child process counter

version 1.3.13
  - new mode: local (netfilter) mode, without identd (stolen from p3scan)
  - session-loop detection (stolen from p3scan)
  - log signal number of signal causing to abort
  - sent/received bytes logged for each session

version 1.3.12
  - header X-NAT-Path added to messages

version 1.3.11
  - clamd support
  - do not even create spool if scan_max_size=0

version 1.3.10
  - stop spooling at scan_max_size
  - scanning duration now logged
  - 'connection closed' shows which side actually closed the connection
  - ignore errors on spool creation if ignore_errors

version 1.3.9
  - new option: scan_max_size, -1=no limit
  - new command-line option: -v

version 1.3.8
  - new option: source_addr
  - fixed SO_REUSEADDR (was set on other socket than it should be)

version 1.3.7
  - restore errno after got_signal

version 1.3.6
  - new options: leave_on_error, pidfile

version 1.3.5
  - fixed ignore_errors
  - SIGHUP: reopens listening socket only if port>=1024 or UID==0

version 1.3.4
  - listening socket now has SO_REUSEADDR set, otherwise it dies after SIGHUP

version 1.3.3
  - new options: set_user, set_group
  - return 0 if config file is valid

version 1.3.2
  - new option: ignore_errors

version 1.3.0
  - messages moved to configuration

version 1.0.0 (2004.02)
  - first version
