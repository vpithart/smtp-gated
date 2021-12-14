/*
 * 	lang-pl.h
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

/* english messages */
#define MSG_VIRUS_FOUND				"Malware found"
#define MSG_VIRUS_NO_MORE			"Malware found, go away"
#define MSG_VIRUS_LOCKED			"You have been banned because of sending virus or SPAM"
#define MSG_SPAM_FOUND				"Message marked as SPAM, denied"
#define MSG_SCANNER_FAILED			"Scanner failed"
#define MSG_MALFORMED_IP			"Malformed server IP"
#define MSG_CANNOT_CONNECT			"Cannot connect to server"
#define MSG_SPOOL_PROBLEM			"Spool filename problem"
#define MSG_SPOOL_OPEN_FAIL			"Spool open failed"
#define MSG_PIPELINE_FULL			"Pipeline queue full"
#define MSG_LOOKUP_FAILED			"Lookup failed"
#define MSG_LOOKUP_TIMEOUT			"Lookup timeout"
#define MSG_LOOKUP_MISMATCH			"Lookup format mismatch"
#define MSG_LOOKUP_NOMEM			"Lookup out of memory"
#define MSG_LOOKUP_NOTFOUND			"Lookup destination not found"
#define MSG_CONNECT_TIMEOUT			"Connection timeout"
#define MSG_CONNECT_FAILED			"Connection failed"
#define MSG_UNKNOWN_VIRUS			"uknown/nieznany"
#define MSG_SESSION_TIMEOUT			"SMTP session timeout. Closing connection"
#define MSG_SIGN_OFF				"Signing off."
#define MSG_HELLO				"SMTP Proxy, hello"
#define MSG_PROTO_ERROR				"Protocol error"
#define MSG_TRANSACTION_FAILED			"Transaction failed"
#define MSG_UNIMPL_COMMAND			"Command not implemented"
#define MSG_TEMP_UNAVAIL			"Service temporarily unavailable"
#define MSG_MAX_REACHED				"Too many connections, try again later"
#define MSG_MAX_PER_HOST			"Too many connections from your host, try again later"
#define MSG_MAX_PER_IDENT			"Too many connections from you, try again later"
#define MSG_SYSTEM_LOAD				"System load too high, try again later"
#define MSG_NOMEM					"Out of memory"
#define MSG_UNKNOWN_SCANNER			"Unknown scanner type"
#define MSG_UNKNOWN_LOOKUP			"Unknown mode"
#define MSG_AUTH_REQUIRED			"Message denied without autorization"
#define MSG_LOOP_AVOIDANCE			"TPROXY loop avoidance"
#define MSG_DNSBL_REJECT			"Connection rejected due to DNSBL"
#define MSG_SPF_REJECT				"Connection rejected due to SPF, enable SMTP authentication"
#define MSG_SIZE_LIMIT				"Message size limit exceeded"
#define MSG_FIXED_XCLIENT_FAIL			"MTA connection failed (XCLIENT)"
#define MSG_REGEX_HELO				"Forbidden HELO/EHLO"
#define MSG_REGEX_MAIL_FROM			"Forbidden MAIL FROM"
#define MSG_REGEX_RCPT_TO			"Forbidden RCPT TO"
#define MSG_RATE_REJECT				"Rejected due to rate or quota limit"
#define MSG_RATELIMIT_ERROR			"Ratelimiter error"
#define MSG_RATELIMIT_MESSAGES			"Message ratelimit exceeded"
#define MSG_RATELIMIT_RCPTTO			"RCPT TO ratelimit exceeded"
#define MSG_RATELIMIT_RCPTTO_REJECTS		"RCPT TO rejection ratelimit exceeded"
#define MSG_RATELIMIT_HELO			"HELO/EHLO SMTP ratelimit exceeded"
#define MSG_RATELIMIT_MAILFROM			"MAIL FROM ratelimit exceeded"
#define MSG_RATELIMIT_MAILFROM_REJECTS		"MAIL FROM rejection ratelimit exceeded"
#define MSG_RATELIMIT_DST			"Target SMTP servers limit exceeded"
#define MSG_EARLYTALKER				"Next time wait for MTA greeting"
