/*
 * 	options.h
 *
 * 	Copyright (C) 2004-2005 Bart�omiej Korupczynski <bartek@klolik.org>
 *
 * 	This program is free software; you can redistribute it and/or
 * 	modify it under the terms of the GNU General Public License
 * 	as published by the Free Software Foundation; either
 * 	version 2 of the License, or (at your option) any later
 * 	version.
 *
 * 	This program is distributed in the hope that it will be useful,
 * 	but WITHOUT ANY WARRANTY; without even the implied warranty of
 * 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * 	GNU General Public License for more details.
 *
 * 	You should have received a copy of the GNU General Public License
 * 	along with this program; if not, write to the Free Software
 * 	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
 * this file generates:
 * - configuration file syntax
 * - configuration structure
 *
 * all preprocessor conditionals must evaluate to the same results
 * in all file it's included in!
*/


/*
 *  CONFIGURATION
*/

/*
	Defines proxy (host) name, used in banners
*/
CONF_OPT_STR(proxy_name, "*")

/*
	Defined address and port to listen on
*/
CONF_OPT_IP4(bind_address, "0.0.0.0")
CONF_OPT_PORT(port, 9199)

/*
	Defines source IP from which connection to destination
	server is made
*/
CONF_OPT_IP4(outgoing_addr, "0.0.0.0")

/*
	PID and state-dump files
	statefile_perm is octal value.
*/
CONF_OPT_STR(pidfile, "/var/run/smtp-gated/smtp-gated.pid")
CONF_OPT_STR(statefile, "/var/run/smtp-gated/state")
CONF_OPT_OCT(statefile_perm, 0660)
CONF_OPT_ENUM(CONF_FLAG_BITMAP, statefile_type, DUMPFILE_TYPE_HUMAN | DUMPFILE_TYPE_SLOTS, statefile_type_list)

/*
	Defines operating mode
	if local netfilter connectrack should be used for
	getting the IP of destination server.
*/
CONF_OPT_ENUM(CONF_FLAG_NONE, mode, MODE_NONE, mode_list)

/*
	mode: fixed
	Defines fixed IP and port for destination SMTP server
	(used if not empty, overrides netfilter and ident methods)
*/
CONF_OPT_IP4_EMPTY(fixed_server, "")
CONF_OPT_PORT(fixed_server_port, 25)


/*
	mode: remote
	Defined port to connect to remote ident w/ netfilter support
*/
CONF_OPT_PORT(remote_port, 114)
CONF_OPT_INT(remote_udp_retries, 3)
CONF_OPT_INT(remote_udp_secret, 0x00000000)

/*
	User name/UID and Group name/GID to switch to.
	Process priority.
	Chroot() path.
*/
CONF_OPT_STR_EMPTY(chroot_path, "")
CONF_OPT_STR_EMPTY(set_user, "")
CONF_OPT_STR_EMPTY(set_group, "")
CONF_OPT_INT(priority, 0)

/*
	Connect backlog, session buffer, pipeline size, hash size
*/
CONF_OPT_INT(connect_queue, 16)
CONF_OPT_UINT(buffer_size, 1516)
CONF_OPT_UINT(pipeline_size, 128)
CONF_OPT_UINT(pid_hash_size, 4096)
CONF_OPT_UINT(host_hash_size, 4096)
CONF_OPT_INT(enfile_sleep, 5)

/*
	Max number of commands after session is taken over to tolerate before hangup
	Changed only for debugging purposes
*/
CONF_OPT_UINT(on_takeover_cmds, 10)

/*
	Core size, in block units (512B?)
	-1 = no change

	We cannot depend on RLIMIT_* being defined here, as this file gets included
	in different files. So, some of there limit will be used, some will not.
	Another way is to setup HAVE_RLIMIT_* in configure scripts (someday).
*/
#ifdef HAVE_SETRLIMIT
#if defined(HAVE_DECL_RLIMIT_CORE) && HAVE_DECL_RLIMIT_CORE
CONF_OPT_INT(limit_core_size, 64 M)
#endif
#if defined(HAVE_DECL_RLIMIT_AS) && HAVE_DECL_RLIMIT_AS
CONF_OPT_INT(limit_virt_size, 64 M)
#endif
#if defined(HAVE_DECL_RLIMIT_DATA) && HAVE_DECL_RLIMIT_DATA
CONF_OPT_INT(limit_data_size, 64 M)
#endif
#if defined(HAVE_DECL_RLIMIT_FSIZE) && HAVE_DECL_RLIMIT_FSIZE
CONF_OPT_INT(limit_fsize, 100 M)
#endif
#endif

/*
	Defined duration to reject client connections if a virus is detected
	0   no banning
	-1  ban forever
	Lock files go to lock_path directory. Lock files with UID=0 are
	considered as non-existent (and no further locking is done)
	lock_perm is octal value.
*/
CONF_OPT_ENUM(CONF_FLAG_BITMAP, lock_on, LOCK_ON_ANY, lock_on_list)
CONF_OPT_INT(lock_duration, 3600)
CONF_OPT_STR(lock_path, "/var/spool/smtp-gated/lock")
CONF_OPT_OCT(lock_perm, 0660)

/*
	disallow certain commands
*/

CONF_OPT_BOOL(forbid_starttls, 0)

/*
	Script called when SPAM/virus is found.

	All parameters are passed via environment variables.
	Script is run under new session (via setsid), and it's
	return value is ignored.
*/

CONF_OPT_STR_EMPTY(action_script, "")

/*
	Defines spool directory and permissions mask for new files
	as defined for open() function.
	spool_perm as octal value.
*/
CONF_OPT_STR(spool_path, "/var/spool/smtp-gated/msg")
CONF_OPT_OCT(spool_perm, 0660)
CONF_OPT_ENUM(CONF_FLAG_BITMAP, spool_leave_on, LEAVE_ON_ERROR, spool_leave_on_list)

/*
	Some timeouts [s]
*/
// timeout sesji bezposredniej (np. po STARTTLS)
CONF_OPT_UINT(timeout_direct, 300)
// timeout identa
CONF_OPT_UINT(timeout_lookup, 10)
// timeout skanera antywirusowego + antyspamowego
CONF_OPT_UINT(timeout_scanner, 30)
// timeout skanera antyspamowego
CONF_OPT_UINT(timeout_spam, 30)
// timeout (symulowanej) sesji po przechwyceniu
CONF_OPT_UINT(timeout_session, 20)
// nic nie przychodzi, nic nie wychodzi
CONF_OPT_UINT(timeout_idle, 300)
// problemy z polaczeniem
CONF_OPT_UINT(timeout_connect, 30)


/*
	Maximum connections: all, per host and per ident
	max_connections requires RESTART to take effect
	max_per_*_lock: lock if max_per_* limit is exceeded
*/
CONF_OPT_UINT(max_connections, 64)
CONF_OPT_UINT(max_per_host, 8)
#ifdef USE_SHARED_MEM
CONF_OPT_UINT(max_per_ident, 4)
#endif


/*
	Loadavg we should start rejecting connections
	(max_load <= 0 turns off this rejecting)
*/
CONF_OPT_DOUBLE(max_load, 2)

/*
 *	Maximum message (e-mail) size [bytes]
*/

CONF_OPT_UINT(size_limit, 0)

/*
	Maximum size of message to AV scan
*/
CONF_OPT_UINT(scan_max_size, 10000000)

/*
	antispam settings
	block spam if spam_block set, or just log scores if 0
	do not scan messages bigger than spam_max_size
	report message as spam if its score above spam_threshold
	skip antispam if loadavg > spam_max_load
	(spam_max_load <= 0 turns off this skipping)
*/
CONF_OPT_UINT(spam_max_size, 500000)
CONF_OPT_DOUBLE(spam_threshold, 7)
CONF_OPT_DOUBLE(spam_max_load, 1)

/*
	Above this load fallback to direct proxy mode
	(no scanning, just pass all)
*/
//	CONF_OPT_DOUBLE(fallback_direct_load, 30)

/*
	Should we ignore errors and continue if possible?
	i.e. ignore scanner errors
*/
CONF_OPT_BOOL(ignore_errors, 0)

/*
	Leave spool (client message) on certain conditions
*/
//CONF_OPT_BOOL(leave_on_error, 0)
//CONF_OPT_BOOL(leave_on_virus, 0)
//CONF_OPT_BOOL(leave_on_spam, 0)

/*
	Message sender/recipient logging mask
	0: do not log at all
	1: log only if MTA accepts it
	2: log only if MTA rejects it
	3: log always
	4: log as base64(md5(mail))
*/
CONF_OPT_BOOL(log_helo, 0)
CONF_OPT_ENUM(CONF_FLAG_BITMAP|CONF_FLAG_ARBITRARY, log_mail_from, LOG_MAIL_NONE, log_mail_list)
CONF_OPT_ENUM(CONF_FLAG_BITMAP|CONF_FLAG_ARBITRARY, log_rcpt_to, LOG_MAIL_NONE, log_mail_list)

CONF_OPT_UINT(email_length, 64)

/*
	SMTP Authentication request
	no: does not require auth
	yes: requires authorization if MTA advertises it
	required: always require authorization
*/
CONF_OPT_ENUM(CONF_FLAG_NONE, auth_require, AUTH_REQUIRE_NO, auth_require_list)
CONF_OPT_ENUM(CONF_FLAG_BITMAP, auth_skip, 0, auth_skip_list)

/*
	Debugging
	log_level: logging messages with level >= log_level
	default: 7 [DEBUG]
*/
CONF_OPT_ENUM(CONF_FLAG_NONE, log_level, LOG_DEBUG, priority_list)
CONF_OPT_ENUM(CONF_FLAG_NONE, log_facility, LOG_DAEMON, facility_list)

/*
	Defines if proxy header is injected into e-mails
	abuse is arbitrary string, i.e. e-mail abuse@isp
*/
CONF_OPT_STR(nat_header, "X-Nat-Received")
CONF_OPT_ENUM(CONF_FLAG_NONE, nat_header_type, NAT_HEADER_TYPE_GENERIC, nat_header_type_list)
CONF_OPT_STR(spool_header, "X-Proxy-Spool-Info")
//CONF_OPT_INT(spool_header_type, 1)
CONF_OPT_STR_EMPTY(abuse, "")

/*
	Paths for scanners, scanner_path is for stand-alone scanner
*/
CONF_OPT_ENUM(CONF_FLAG_NONE, antivirus_type, AV_NONE, antivirus_type_list)
CONF_OPT_STR(antivirus_path, "/var/run/clamav/clamd.ctl")
// CONF_OPT_STR(antivirus_regex, "")	// script, pipe

CONF_OPT_ENUM(CONF_FLAG_NONE, antispam_type, AS_NONE, antispam_type_list)
CONF_OPT_STR(antispam_path, "/var/run/spamd/spamd_socket")
// CONF_OPT_STR(antispam_regex, "")	// script, pipe

/*
 * DSPAM configuration
*/
#ifdef SCANNER_LIBDSPAM
CONF_OPT_STR(dspam_storage, "/var/spool/smtp-gated/dspam")
#endif

/*
 * earlytalker
*/
CONF_OPT_BOOL(earlytalker, 1)

#ifdef USE_REGEX
CONF_OPT_STR_EMPTY(regex_enforce_helo, "")
CONF_OPT_STR_EMPTY(regex_reject_helo, "")
CONF_OPT_STR_EMPTY(regex_enforce_mail_from, "")
CONF_OPT_STR_EMPTY(regex_reject_mail_from, "")
CONF_OPT_STR_EMPTY(regex_enforce_rcpt_to, "")
CONF_OPT_STR_EMPTY(regex_reject_rcpt_to, "")
#endif

/*
 * DNSBL lookup domains, comma delimited
*/
CONF_OPT_STR_EMPTY(dnsbl, "")

/*
 * SPF
*/
#ifdef USE_SPF
CONF_OPT_ENUM(CONF_FLAG_NONE, spf, 0, spf_list)
CONF_OPT_BOOL(spf_log_only, 0)
CONF_OPT_IP4_EMPTY(spf_fixed_ip, "")
#endif

/*
	rate limiting (quota)
	0   no limit
*/

CONF_OPT_STR(ratelimit_path, "/var/spool/smtp-gated/ratelimit")
CONF_OPT_INT(ratelimit_dst_expiration, -1)
CONF_OPT_INT(ratelimit_expiration, 0)
CONF_OPT_UINT(ratelimit_generation, 0)
CONF_OPT_UINT(ratelimit_connections, 0)
CONF_OPT_UINT(ratelimit_messages, 0)
CONF_OPT_UINT(ratelimit_recipients, 0)
CONF_OPT_UINT(ratelimit_bytes, 0)
CONF_OPT_UINT(ratelimit_mailfrom_rejects, 0)
CONF_OPT_UINT(ratelimit_rcptto_rejects, 0)
CONF_OPT_UINT(ratelimit_auth_rejects, 0)
// CONF_OPT_BOOL(ratelimit_account_ssl, 0)


#ifdef USE_PGSQL
/*
	PostgreSQL support variables; NOT IMPLEMENTED YET
*/
CONF_OPT_STR_EMPTY(db_path, "")
CONF_OPT_STR_EMPTY(db_name, "")
CONF_OPT_STR_EMPTY(db_user, "")
CONF_OPT_STR_EMPTY(db_pass, "")
CONF_OPT_STR_EMPTY(db_condition, "SELECT 1 FROM found WHERE ident='%i' OR host='%h' AND when > now() - 7200 LIMIT 1")
CONF_OPT_STR_EMPTY(on_virus, "UPDATE")
CONF_OPT_STR_EMPTY(on_virus_2, "INSERT INTO found (what,name,ident,when) VALUES ('VIR','%v','%i',now()')")
CONF_OPT_STR_EMPTY(on_virus_notify, "NOTIFY virus_found")
CONF_OPT_STR_EMPTY(on_spam, "")
CONF_OPT_STR_EMPTY(on_spam_2, "INSERT INTO found (what,name,ident,when) VALUES ('SPAM','%s','%i',now()')")
CONF_OPT_STR_EMPTY(on_spam_notify, "")
CONF_OPT_STR_EMPTY(on_host_flood, "")
CONF_OPT_STR_EMPTY(on_host_flood_2, "")
CONF_OPT_STR_EMPTY(on_host_flood_notify, "INSERT INTO ...")
CONF_OPT_STR_EMPTY(on_ident_flood, "")
CONF_OPT_STR_EMPTY(on_ident_flood_2, "")
CONF_OPT_STR_EMPTY(on_ident_flood_notify, "INSER INTO ...")
#endif


/*
	Messages
*/
CONF_OPT_STR_EMPTY(locale, "")

CONF_OPT_STR_VERBOSE(msg_virus_found, MSG_VIRUS_FOUND)
CONF_OPT_STR_VERBOSE(msg_virus_no_more, MSG_VIRUS_NO_MORE)
CONF_OPT_STR_VERBOSE(msg_virus_locked, MSG_VIRUS_LOCKED)
CONF_OPT_STR_VERBOSE(msg_spam_found, MSG_SPAM_FOUND)
CONF_OPT_STR_VERBOSE(msg_unknown_virus, MSG_UNKNOWN_VIRUS)
CONF_OPT_STR_VERBOSE(msg_scanner_failed, MSG_SCANNER_FAILED)
CONF_OPT_STR_VERBOSE(msg_malformed_ip, MSG_MALFORMED_IP)
CONF_OPT_STR_VERBOSE(msg_cannot_connect, MSG_CANNOT_CONNECT)
CONF_OPT_STR_VERBOSE(msg_spool_problem, MSG_SPOOL_PROBLEM)
CONF_OPT_STR_VERBOSE(msg_spool_open_fail, MSG_SPOOL_OPEN_FAIL)
CONF_OPT_STR_VERBOSE(msg_pipeline_full, MSG_PIPELINE_FULL)
CONF_OPT_STR_VERBOSE(msg_lookup_failed, MSG_LOOKUP_FAILED)
CONF_OPT_STR_VERBOSE(msg_lookup_notfound, MSG_LOOKUP_NOTFOUND)
CONF_OPT_STR_VERBOSE(msg_lookup_timeout, MSG_LOOKUP_TIMEOUT)
CONF_OPT_STR_VERBOSE(msg_lookup_mismatch, MSG_LOOKUP_MISMATCH)
CONF_OPT_STR_VERBOSE(msg_lookup_nomem, MSG_LOOKUP_NOMEM)
CONF_OPT_STR_VERBOSE(msg_lookup_unknown, MSG_UNKNOWN_LOOKUP)
CONF_OPT_STR_VERBOSE(msg_connect_timeout, MSG_CONNECT_TIMEOUT)
CONF_OPT_STR_VERBOSE(msg_connect_failed, MSG_CONNECT_FAILED)
CONF_OPT_STR_VERBOSE(msg_session_timeout, MSG_SESSION_TIMEOUT)
CONF_OPT_STR_VERBOSE(msg_sign_off, MSG_SIGN_OFF)
CONF_OPT_STR_VERBOSE(msg_hello, MSG_HELLO)
CONF_OPT_STR_VERBOSE(msg_proto_error, MSG_PROTO_ERROR)
CONF_OPT_STR_VERBOSE(msg_transaction_failed, MSG_TRANSACTION_FAILED)
CONF_OPT_STR_VERBOSE(msg_unimpl_command, MSG_UNIMPL_COMMAND)
CONF_OPT_STR_VERBOSE(msg_temp_unavail, MSG_TEMP_UNAVAIL)
CONF_OPT_STR_VERBOSE(msg_max_reached, MSG_MAX_REACHED)
CONF_OPT_STR_VERBOSE(msg_max_per_host, MSG_MAX_PER_HOST)
CONF_OPT_STR_VERBOSE(msg_max_per_ident, MSG_MAX_PER_IDENT)
CONF_OPT_STR_VERBOSE(msg_system_load, MSG_SYSTEM_LOAD)
CONF_OPT_STR_VERBOSE(msg_nomem, MSG_NOMEM)
CONF_OPT_STR_VERBOSE(msg_unknown_scanner, MSG_UNKNOWN_SCANNER)
CONF_OPT_STR_VERBOSE(msg_auth_required, MSG_AUTH_REQUIRED)
CONF_OPT_STR_VERBOSE(msg_loop_avoidance, MSG_LOOP_AVOIDANCE)
CONF_OPT_STR_VERBOSE(msg_size_limit, MSG_SIZE_LIMIT)
CONF_OPT_STR_VERBOSE(msg_fixed_xclient_fail, MSG_FIXED_XCLIENT_FAIL)
CONF_OPT_STR_VERBOSE(msg_dnsdb_reject, MSG_DNSBL_REJECT)
CONF_OPT_STR_VERBOSE(msg_spf_reject, MSG_SPF_REJECT)
CONF_OPT_STR_VERBOSE(msg_rate_reject, MSG_RATE_REJECT)
CONF_OPT_STR_VERBOSE(msg_ratelimit_error, MSG_RATELIMIT_ERROR)
CONF_OPT_STR_VERBOSE(msg_ratelimit_messages, MSG_RATELIMIT_MESSAGES)
CONF_OPT_STR_VERBOSE(msg_ratelimit_rcptto, MSG_RATELIMIT_RCPTTO)
CONF_OPT_STR_VERBOSE(msg_ratelimit_rcptto_rejects, MSG_RATELIMIT_RCPTTO_REJECTS)
CONF_OPT_STR_VERBOSE(msg_ratelimit_helo, MSG_RATELIMIT_HELO)
CONF_OPT_STR_VERBOSE(msg_ratelimit_mailfrom, MSG_RATELIMIT_MAILFROM)
CONF_OPT_STR_VERBOSE(msg_ratelimit_mailfrom_rejects, MSG_RATELIMIT_MAILFROM_REJECTS)
CONF_OPT_STR_VERBOSE(msg_ratelimit_dst, MSG_RATELIMIT_DST)
CONF_OPT_STR_VERBOSE(msg_earlytalker, MSG_EARLYTALKER)
#ifdef USE_REGEX
CONF_OPT_STR_VERBOSE(msg_regex_helo, MSG_REGEX_HELO)
CONF_OPT_STR_VERBOSE(msg_regex_mail_from, MSG_REGEX_MAIL_FROM)
CONF_OPT_STR_VERBOSE(msg_regex_rcpt_to, MSG_REGEX_RCPT_TO)
#endif
