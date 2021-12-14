/*
 * 	smtp-gated.c
 *
 *	SMTP Transparent Proxy
 *	Bartlomiej Korupczynski
 *	http://smtp-proxy.klolik.org
 *	(c) Warszawa 2004-2005
 *	GNU GPL License
 *
 *	Copyright (C) 2004-2005 Bart�omiej Korupczynski <bartek@klolik.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either
 *	version 2 of the License, or (at your option) any later
 *	version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*
 * 	headers
*/

#define _GNU_SOURCE
#define _USE_BSD

#define _SMTP_GATED_C_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <locale.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
//#include <assert.h>
//#include <err.h>


#ifdef USE_NAT_TPROXY
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT	19
#endif
#endif

#ifdef USE_PGSQL
#include <libpq-fe.h>
#error USE_PGSQL not yet implemented
#endif

#include "confvars.h"
#include "smtp-gated.h"
#include "lang.h"
#include "conffile.h"
#include "scan.h"
#include "dump.h"
#include "lockfile.h"
#include "spool.h"
#include "lookup.h"
#include "util.h"
#include "daemon.h"
#include "md5.h"
#include "compat.h"
#include "action.h"
#include "dnsbl.h"
#include "ratelimit.h"
#ifdef USE_REGEX
#include "regex.h"
#endif
#ifdef USE_SPF
#include "spf.h"
#endif

//#define MEMLEAK_TESTING		4

/*
 * 	constants
*/



static const int one = 1;

// max. 8 chars (indexed by conn_state)
char *conn_states[] = {
	"start", "helo",
	"ident", "connect", "pre",
	"spf",
	"dnsdb",
	"data", "bdat", "direct",
	"scan", "scan1", "scan2", "spam", "spam1", "spam2",
	"post", "rset", "quit"
};

struct option_enum nat_header_type_list[] = {
	{ "none", NAT_HEADER_TYPE_NONE },
	{ "generic", NAT_HEADER_TYPE_GENERIC },
	{ "ip-only", NAT_HEADER_TYPE_IP_ONLY },
	{ NULL }
};

struct option_enum mode_list[] = {
	{ "none", MODE_NONE },
	{ "fixed", MODE_FIXED },
	{ "fixed+xclient", MODE_FIXED_XCLIENT },
//	{ "fixed+xclient-proxy", MODE_FIXED_XCLIENT_PROXY },
	{ "remote", MODE_REMOTE },
	{ "remote-udp", MODE_REMOTE_UDP },
	{ "getsockname", MODE_GETSOCKNAME },
#ifdef USE_NAT_NETFILTER
	{ "netfilter", MODE_NETFILTER },
#endif
#ifdef USE_NAT_TPROXY
	{ "tproxy", MODE_TPROXY },
	{ "tproxy,netfilter", MODE_TPROXY_OR_NETFILTER },
#endif
#ifdef USE_NAT_IPFW
	{ "ipfw", MODE_IPFW },
#endif
#ifdef USE_NAT_IPFILTER
	{ "ipfilter", MODE_IPFILTER },
#endif
#ifdef USE_NAT_PF
	{ "pf", MODE_PF },
#endif
	{ NULL }
};

// important: descending order!
struct option_enum log_mail_list[] = {
//	{ "any", LOG_MAIL_ACCEPTED|LOG_MAIL_REJECTED },
	{ "accepted", LOG_MAIL_ACCEPTED },
	{ "rejected", LOG_MAIL_REJECTED },
	{ "base64", LOG_MAIL_BASE64 },
	{ "off", LOG_MAIL_NONE },
	{ "no", LOG_MAIL_NONE },
	{ "none", LOG_MAIL_NONE },
	{ NULL }
};

struct option_enum auth_require_list[] = {
	{ "mandatory", AUTH_REQUIRE_MANDATORY },
	{ "ifsupported", AUTH_REQUIRE_IFSUPPORTED },
	{ "no", AUTH_REQUIRE_NO },
	{ NULL }
};

struct option_enum auth_skip_list[] = {
	{ "direct", AUTH_SKIP_DIRECT },
	{ "antivir", AUTH_SKIP_ANTIVIR },
	{ "antispam", AUTH_SKIP_ANTISPAM },
	{ "regex", AUTH_SKIP_REGEX },
	{ "dnsbl", AUTH_SKIP_DNSBL },
	{ "none", AUTH_SKIP_NONE },
	{ NULL }
};

struct option_enum facility_list[] = {
//	{ "kern", LOG_KERN },
	{ "user", LOG_USER },
	{ "mail", LOG_MAIL },
	{ "daemon", LOG_DAEMON },
	{ "auth", LOG_AUTH },
//	{ "lpr", LOG_LPR },
	{ "news", LOG_NEWS },
//	{ "uucp", LOG_UUCP },
#ifdef LOG_AUDIT
	{ "audit", LOG_AUDIT },
#endif
//	{ "cron", LOG_CRON },
#ifdef LOG_AUTHPRIV
	{ "authpriv", LOG_AUTHPRIV },
#endif
#ifdef LOG_FTP
//	{ "ftp", LOG_FTP },
#endif
	{ "local0", LOG_LOCAL0 },
	{ "local1", LOG_LOCAL1 },
	{ "local2", LOG_LOCAL2 },
	{ "local3", LOG_LOCAL3 },
	{ "local4", LOG_LOCAL4 },
	{ "local5", LOG_LOCAL5 },
	{ "local6", LOG_LOCAL6 },
	{ "local7", LOG_LOCAL7 },
	{ NULL }
};

struct option_enum priority_list[] = {
	{ "alert", LOG_ALERT },
	{ "crit", LOG_CRIT },
	{ "debug", LOG_DEBUG },
	{ "emerg", LOG_EMERG },
	{ "err", LOG_ERR },
	{ "info", LOG_INFO },
	{ "notice", LOG_NOTICE },
	{ "warning", LOG_WARNING },
	{ NULL }
};


/*
	global variables
*/

char *config_file = NULL;

int child_status = 0;
int children = 0;
int i_am_a_child = 0;

volatile sig_atomic_t force_reconfig = 0;
volatile sig_atomic_t force_finish = 0;
volatile sig_atomic_t force_dump = 0;
volatile sig_atomic_t child_died = 0;
volatile sig_atomic_t timedout = 0;

#ifdef USE_SHARED_MEM
// child_slot i i_am_a_child sie poniekad dubluja
#define I_AM_A_CHILD()	(child_slot != -1)
int child_slot = -1;
int conn_shmid = -1;
int stat_shmid = -1;
#endif

int max_connections_real;
struct scoreboard_t *connections = NULL;
struct stat_info *stats = NULL;

/* separated from shared memory due to security and stability reasons */
pid_t *pids = NULL;

/* cache&hash for high max_connections */
#define SLOT_NOT_FOUND	-1
int pid_hash_size_real = 1;
struct slot_hash_entry_t *free_slots = NULL;
struct slot_hash_entry_t **pid_hash_table = NULL;
int host_hash_size_real = 1;
struct host_hash_entry_t **host_hash_table = NULL;

int ip_hash_size_real = 1024;


/*
 * 	forward functions
*/

void cleanup();
void dump_state();


char* compile_date()
{
	return __DATE__ " " __TIME__;
}

static inline void debug_stage(char *str)
{
	if (!IS_FLAG_SET(foreground, FORE_DEBUG_STAGE)) return;

	log_action(LOG_ERR, "DEBUG: %s", str);
	fdprintf(1, "DEBUG-STAGE:%s\n", str);
#if 0
	int res, i;
	for (i=8; i>0; i--) {
		if ((res = fdprintf(1, "%s\n", str)) != -1)
			break;
		if (res == -1 && errno == EINTR)
			continue;
		log_action(LOG_ERR, "DEBUG: errno=%s", strerror(errno));
		break;
	}
#endif
}

/*
 * 	deklaracje funkcji wprzod
*/

// void wait_for_quit(struct session_t *data, char* format, ...);
void pipeline_full(struct session_t *data);

/*
 * 	funkcje pomocnicze
*/

inline void upcase(char *str)
{
	if (str == NULL) return;

	for (; str[0] != '\0'; str++) {
		if (str[0] >= 'a' && str[0] <= 'z') str[0] -= ('a'-'A');
	}
}

inline int resp_code(char *s)
{
	if (s[0]<'0' || s[0]>'9' || s[1]<'0' || s[1]>'9' || s[2]<'0' || s[2]>'9') return -1;

	return 100*((int) (s[0]-'0')) + 10*((int) (s[1]-'0')) + ((int) (s[2]-'0'));
}



/*
 * 	Logowanie
*/

#ifdef USE_SHARED_MEM
void set_dump_state(conn_state s)
{
	connections[child_slot].state = s;
}
#endif

void bug(const char* filename, const char* func, int lineno, const char* format, ...)
{
	va_list ap;
	char msg[PRINTF_SIZE];

	va_start(ap, format);
	int res = vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);

	if (res < 0)
		strncpy(msg, "(vsprintf error)", sizeof(msg));

	TERMINATE_STRING(msg);

	log_action(LOG_CRIT, "!BUG! %s:%s:%d %s", filename, func, lineno, msg);

	if (!stats)
		return;

	stats->child_bugs++;
	stats->child_bug_last = time(NULL);
}

/*
	return:
	=0	success
	<0	errno
	1	data truncated
*/

// wyslij odpowiedz code " " [ class "." subject "." detail ]
// code = tradycyjny kod odpowiedzi
// esc2 = subject kodu rozszerzonego
// esc3 = detail kodu rozszerzonego
//

int response(struct session_t *data, struct response_code resp, char *format, ...)
{
	int class, res, len;
	va_list ap;
	char buf[PRINTF_SIZE];
	char *cur;

	class = resp.generic / 100;

	if (data->enhancedstatuscodes && (class == 2 || class == 4 || class == 5) && (resp.subject != -1)) {
		// kod rozszerzony
		len = snprintf(buf, sizeof(buf), "%03d %d.%d.%d ", resp.generic, class, resp.subject, resp.detail);
	} else {
		// kod zwykly
		len = snprintf(buf, sizeof(buf), "%03d ", resp.generic);
	}

	if (len == -1 || len > sizeof(buf)) {	// glibc 2.0.6 and glibc 2.1
		errno = ENOMEM;
		return -1;
	}

	va_start(ap, format);
	res = vsnprintf(buf+len, sizeof(buf)-len, format, ap);
	va_end(ap);

	if (res == -1 || res > sizeof(buf)-len) {
		errno = ENOMEM;
		return -1;
	}

	len += res;
	cur = buf;
	while (len > 0) {
		if (timedout) {
			CLEAR_TIMEOUT();
			errno = ETIMEDOUT;
			return -1;
		}

	       	if ((res = write(data->client, cur, len)) == -1) {
//			if (errno == EINTR) continue;
			return -1;
		}

		if (res == 0) {
			// a nie ECONNRESET?
			errno = ETIMEDOUT;
			return -1;
		}

		len -= res;
		cur += res;
	}

	return res;
} /* response() */

/*
 * 	usuwanie i przywracanie CRLF
*/

inline void save_remove_crlf(char *buffer, char *pos, char **replace_pos, char *replace_char)
{
	if ((pos > buffer) && (*(pos-1) == '\r')) {
		*replace_pos = pos-1;
		*replace_char = **replace_pos;
		**replace_pos = '\0';
	} else {
		*replace_pos = pos;
		*replace_char = **replace_pos;
		**replace_pos = '\0';
	}
} /* rave_remove_crlf() */

inline void restore_crlf(/*@unused@*/ char *buffer, /*@unused@*/ char *pos, char **replace_pos, char *replace_char)
{
	**replace_pos = *replace_char;
} /* restore_crlf() */

/*
 * 	pipeline - kolejkowanie
*/

void queue_commandp(smtp_command_t command, struct session_t *data, pipeline_arg_t parm1, pipeline_arg_t parm2)
{
	struct pipeline_t *ce;

	assert(data->command_pos_client < data->pipeline_size);

//	log_action(LOG_DEBUG, "QUEUE:QUEUE %d at %d", command, data->command_pos_client);
	ce = &data->pipeline[data->command_pos_client];
	ce->cmd = command;
	ce->parm1 = parm1;
	ce->parm2 = parm2;

	data->command_pos_client++;
	data->command_pos_client %= data->pipeline_size;

	// queue full
	if (data->command_pos_client == data->command_pos_server)
		pipeline_full(data);
} /* queue_commandp() */

inline void queue_command(smtp_command_t command, struct session_t *data)
{
	return queue_commandp(command, data, arg_t_p(NULL), arg_t_p(NULL));
} /* queue_command() */

smtp_command_t poll_commandp(struct session_t *data, pipeline_arg_t *parm1, pipeline_arg_t *parm2)
{
	smtp_command_t command;
	struct pipeline_t *ce;

	assert(data->command_pos_server < data->pipeline_size);

	if (data->command_pos_client == data->command_pos_server) {
//		log_action(LOG_DEBUG, "QUEUE:POLL no commands queued");
		return COMMAND_NONE;
	}

	ce = &data->pipeline[data->command_pos_server];
	command = ce->cmd;
	if (parm1) *parm1 = ce->parm1;
	if (parm2) *parm2 = ce->parm2;

//	log_action(LOG_DEBUG, "QUEUE:POLL %d at %d", command, data->command_pos_server);
	return command;
} /* poll_commandp() */

inline void dequeue_command(struct session_t *data)
{
	// move to next
	data->command_pos_server++;
	data->command_pos_server %= data->pipeline_size;
} /* dequeue_command() */


/*
 *	hash&tables
*/

/*
----------------------------
 MEMORY UTILISATION SUMMARY
----------------------------
type         before    after
----------------------------
VmData          200      200
VmExe            92       92
VmHWM           868     1092
VmLck             0        0
VmLib          2024     2024
VmPTE            16       16
VmPeak         2472     2472
VmRSS           864     1088
VmSize         2468     2468
VmStk            84       84
sum(diff)       -->      448
----------------------------
--- DURATION: 0

--- 998mem-leak.t: WARNING: Memory usage threshold exceeded! Possible memory leak
*/

#warning run-test.pl --long: possible memory leak

inline int ip_hash(uint32_t ip)
{
	return (ip % ip_hash_size_real);
}

// TODO: merge host_count and host_inc to remove searching twice; return count & pointer to hs?
int host_count(in_addr_t host, struct host_hash_entry_t **slot)
{
	struct host_hash_entry_t *hs;

	for (hs = host_hash_table[ip_hash(host)]; hs!=NULL; hs=hs->next) {
		if (hs->host != host) continue;
		if (slot) *slot = hs;
		return hs->count;
	}

	if (slot) *slot = NULL;
	return 0;
}

struct host_hash_entry_t * host_inc(in_addr_t host, struct host_hash_entry_t *slot)
{
	struct host_hash_entry_t *hs;

	if (host_hash_table == NULL)
		return NULL;

	if (slot) {
		// use cached slot
		slot->count++;
		return slot;
	}

	int hash = ip_hash(host);
	for (hs = host_hash_table[hash]; hs!=NULL; hs=hs->next) {
		if (hs->host != host) continue;
		hs->count++;
		return hs;
	}

	slot = malloc(sizeof(*slot));
	slot->next = host_hash_table[hash];
	slot->host = host;
	slot->count = 1;
	host_hash_table[hash] = slot;
	return slot;
}

// TODO: cache pointer to host_hash_entry in connections[]? would be faster if no need for free()
void host_dec(in_addr_t host)
{
	struct host_hash_entry_t *entry, *prev;
	int hash = ip_hash(host);

	for (prev = NULL, entry = host_hash_table[hash]; entry!=NULL; prev = entry, entry=entry->next) {
		if (entry->host != host) continue;

		if (--entry->count)
			return;

		// we were the last one
		if (prev)
			prev->next = entry->next;
		else
			host_hash_table[hash] = entry->next;

		free(entry);
		return;
	}

	log_action(LOG_WARNING, "!BUG! host_dec(%d.%d.%d.%d) has not found host entry!", NIPQUAD(host));
	return;
}

inline int pid_hash(pid_t pid)
{
	return (((int) pid) % pid_hash_size_real);
}

#if 0
int slot_by_pid(pid_t pid)
{
	if (pid_hash_table) {
		struct slot_hash_entry_t *entry;

		for (entry = pid_hash_table[pid_hash(pid)]; entry!=NULL; entry=entry->next) {
			if (pids[entry->slot] != pid) continue;
			return entry->slot;
		}

		return -1;
	} else {
		int slot;

		for (slot=0; slot<max_connections_real; slot++) {
			if (pids[slot] == pid) return slot;
		}

		return -1;
	}
}
#endif

/* takes first free slot from the pool */
int slot_peek()
{
	if (!free_slots) return SLOT_NOT_FOUND;
	return free_slots->slot;
}

int slot_use(int slot, pid_t pid)
{
	if (pid_hash_table == NULL) return -1;
	if (free_slots == NULL) {
		log_action(LOG_ALERT, "!BUG! %s: no free_slots but got %d!", __FUNCTION__, slot);
		return -1;
	}

	if (free_slots->slot != slot) {
		log_action(LOG_ALERT, "!BUG! %s: using bogus slot %d instead of %d", __FUNCTION__, slot, free_slots->slot);
		return -1;
	}

	int hash = pid_hash(pid);

	struct slot_hash_entry_t *slotent = free_slots;
	free_slots = slotent->next;

	slotent->next = pid_hash_table[hash];
	pid_hash_table[hash] = slotent;
	return 0;
}

int slot_hash_find_and_remove(pid_t pid)
{
	struct slot_hash_entry_t *entry, *prev;
	int hash = pid_hash(pid);

	for (prev = NULL, entry = pid_hash_table[hash]; entry!=NULL; prev = entry, entry=entry->next) {
		if (pids[entry->slot] != pid) continue;

		/* remove from pid_hash_table */
		if (prev)
			prev->next = entry->next;
		else
			pid_hash_table[hash] = entry->next;

		/* insert into free_slots */
		entry->next = free_slots;
		free_slots = entry;

		return entry->slot;
	}

	return SLOT_NOT_FOUND;
}

int slot_pid_find(pid_t pid)
{
	int i;

	for (i=0; i<max_connections_real; i++) {
		if (pids[i] == pid)
			return i;
	}

	return SLOT_NOT_FOUND;
}


/* removes slot from the hash and returns to the free pool */
int slot_free_by_pid(pid_t pid)
{
	int slot = (pid_hash_table) ? slot_hash_find_and_remove(pid) : slot_pid_find(pid);

	/* not found? should never ever happen! */
	/* 20111113#BK# well, in fact it can: if action script was forked in the main loop */
	if (slot == SLOT_NOT_FOUND) {
//		log_action(LOG_DEBUG, "!BUG! %s: pid %" FORMAT_PID_T " not found!", __FUNCTION__, pid);
		return slot;
	}

	if (pid_hash_table)
		host_dec(connections[slot].src);

	// empty slot
	pids[slot] = 0;
#ifdef USE_SHARED_MEM
	connections[slot].ident_ok = 0;
#endif

	return slot;
}


/*
 * 	signals
*/

void child_reaper()
{
	pid_t pid;

	for (;;) {
		pid = wait3((int *) &child_status, WNOHANG, NULL);

		// brak kolejnych bachorow (teoretycznie)
		if (pid == 0) break;

		// error
		if (pid == -1) {
			if (errno == ECHILD) break;
			if (errno == EINTR) continue;

			log_action(LOG_ERR, "!ERR! wait3() returned: %s", strerror(errno));
			break;
		}

		if (WIFSIGNALED(child_status)) {
			log_action(LOG_ALERT, "!BUG! Child %" FORMAT_PID_T " exited on signal %d", pid, WTERMSIG(child_status));
			stats->child_crashes++;
			stats->child_crash_last = time(NULL);
		}

		if (!i_am_a_child && connections) {
			debug_stage("CHILD_GONE");
			// this could be connection process dying - ok
			// but could also be a action script after host-lock (spawn from main loop)
			slot_free_by_pid(pid);
		}

		if (children > 0) children--;
	}
} /* child_reaper() */

void got_signal(int signum)
{
	switch (signum) {
		case SIGCHLD:
			child_died = 1;
			return;
		case SIGALRM:
			timedout = 1;
			return;
		case SIGHUP:
			force_reconfig = 1;
			return;
		case SIGUSR1:
			force_dump = 1;
			return;
		case SIGUSR2:
			return;
		case SIGTERM:
		case SIGQUIT:
			force_finish = 1;
			return;
		default:
			log_action(LOG_INFO, "Received signal %s [%d], exiting.", strsignal(signum), signum);
			cleanup();
			exit(0);
	}
} /* got_signal() */

void cleanup()
{
	if (!i_am_a_child) {
		pidfile_remove(config.pidfile);
#ifdef USE_SHARED_MEM
		shmfreeid(conn_shmid);
		shmfreeid(stat_shmid);
	} else {
		if (child_slot != -1) {
			SHARED_CONN_STATUS(ident_ok, 0);
		}
#endif
	}
} /* cleanup() */

inline void cleanup_exit(int code)
{
	cleanup();
	exit(code);
}


#ifdef SIGXFSZ
#define COND_SIGXFSZ	SIGXFSZ,
#else
#define COND_SIGXFSZ
#endif

int setup_signal()
{
	return setup_signals(&got_signal,
		ARRAY(int, SIGHUP, SIGINT, SIGQUIT, SIGUSR1, SIGUSR2, SIGTERM, SIGALRM, SIGCHLD, 0),
		ARRAY(int, SIGPIPE, COND_SIGXFSZ 0));
} /* setup_signal() */



/*
 * 	line reading
*/


// TODO flush_buffers()
// TODO: wysle drugi raz np. BDAT ...
// mysi pominac to co juz trafilo do func()
void flush_buffers(struct session_t *data)
{
	ssize_t res;
	char *buf;

	buf = data->cli_buf;
	while (data->cli_size > 0) {
		if ((res = write(data->server, buf, data->cli_size)) == -1) {
			if (errno == EINTR) continue;
			break;
		}

		data->cli_size -= res;
		buf += res;
	}

	buf = data->srv_buf;
	while (data->srv_size > 0) {
		if ((res = write(data->client, buf, data->srv_size)) == -1) {
			if (errno == EINTR) continue;
			break;
		}

		data->srv_size -= res;
		buf += res;
	}
} /* flush_buffers() */



void helo(int client)
{
	fdprintf(client, "220 %s SMTP\r\n", config.proxy_name);
} /* helo() */

/*
 * oczekiwanie na QUIT
 * symuluje sesje SMTP, w oczekiwaniu na QUIT klienta
*/

line_status local_callback(char* buffer, char* pos, /*@unused@*/ int size, void *ptr)
{
	char *replace_pos, replace_char;
	struct session_t *data = ptr;

	if (!pos) return LINE_OK;

	save_remove_crlf(buffer, pos, &replace_pos, &replace_char);

	if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%" FORMAT_PID_T "] <= %s\n", getpid(), buffer);

	// close after couple of meaningless commands
	data->command_count++;
	if (data->command_count > config.on_takeover_cmds) {
//		fdprintf(data->client, "554 %s %s\r\n", config.proxy_name, config.msg_transaction_failed);
		response(data, ER(554,5,0), "%s %s\r\n", config.proxy_name, config.msg_transaction_failed);
		return LINE_CLOSED;
	}

	if (strcasecmp(buffer, "QUIT") == 0) {
//		fdprintf(data->client, "221 %s %s\r\n", config.proxy_name, config.msg_sign_off);
		response(data, ER(221,0,0), "%s %s\r\n", config.proxy_name, config.msg_sign_off);
		return LINE_CLOSED;
	} else if ((strcasecmp(buffer, "NOOP") == 0) ||
		   (strcasecmp(buffer, "RSET") == 0)) {
//		fdprintf(data->client, "250 OK\r\n");
		response(data, ER(250,0,0), "OK\r\n");
	} else if ((strncasecmp(buffer, "EHLO ", 5) == 0) ||
		   (strncasecmp(buffer, "HELO ", 5) == 0)) {
//		fdprintf(data->client, "250 %s %s\r\n", config.proxy_name, config.msg_hello);
		response(data, ER(250,0,0), "%s %s\r\n", config.proxy_name, config.msg_hello);
	} else if (((strncasecmp(buffer, "RCPT TO:", 5) == 0)) ||
		   ((strcasecmp(buffer, "DATA") == 0))) {
//		fdprintf(data->client, "503 %s %s\r\n", config.proxy_name, config.msg_proto_error);
		response(data, ER(503,5,1), "%s %s\r\n", config.proxy_name, config.msg_proto_error);
	} else if ((strncasecmp(buffer, "MAIL FROM:", 5) == 0)) {
//		fdprintf(data->client, "451 %s %s\r\n", config.proxy_name, data->message);
		response(data, ER(451,3,2), "%s %s\r\n", config.proxy_name, data->message);
	} else {
//		fdprintf(data->client, "502 %s %s\r\n", config.proxy_name, config.msg_unimpl_command);
		response(data, ER(502,5,2), "%s %s\r\n", config.proxy_name, config.msg_unimpl_command);
	}

	return LINE_OK;
} /* local_callback() */

// bez \r\n na koncu!

void wait_for_quit(struct session_t* data, char* format, ...)
{
	va_list ap;
	char cli_buf[512];
	int cli_size, res;

	// dla TPROXY
	if ((data->mode == MODE_TPROXY || data->mode == MODE_TPROXY_OR_NETFILTER) && drop_privileges() != 0) {
		SAFE_CLOSE(data->server);
		// still running as root? :/ don't be nice, just quit
		log_action(LOG_CRIT, "ERROR: Could not drop privileges, quitting immediately");
		fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_connect_failed);
		SAFE_CLOSE(data->client);
		exit(0);
	}

	// inicjacja unii dla wait_for_quit
	data->command_count = 0;

	va_start(ap, format);
	if (vasprintf(&data->message, format, ap) == -1) {
		data->message = NULL;
	}
	va_end(ap);

	SHARED_CONN_STATUS(state, CONN_QUIT);
	log_action(LOG_WARNING, "SESSION TAKEOVER: src=%s, ident=%s, trns=%d, reason=%s",
		data->origin_str, data->ident, data->transaction, data->message);

	cli_size = 0;
	SET_TIMEOUT(config.timeout_session);

	for (;;) {
		assert(cli_size < sizeof(cli_buf));

		if (timedout) {
			CLEAR_TIMEOUT();
			res = LINE_EINTR;
			response(data, ER(421,4,2), "%s %s\r\n", config.proxy_name, config.msg_session_timeout);
			log_action(LOG_INFO, "CLOSE:TAKEN %s", config.msg_session_timeout);
			break;
		}

		res = fdgetline_cb(data->client, cli_buf, sizeof(cli_buf), &cli_size, &local_callback, data, NULL);
/*
		if (res == LINE_EINTR) {
			CLEAR_TIMEOUT();
			response(data, ER(421,4,2), "%s %s\r\n", config.proxy_name, config.msg_session_timeout);
			log_action(LOG_INFO, "CLOSE:TAKEN %s", config.msg_session_timeout);
			break;
		}
*/
		if (res == LINE_CLOSED) break;
	}

	SAFE_CLOSE(data->client);
	cleanup();

	if (res != LINE_EINTR) log_action(LOG_DEBUG, "CLOSE:TAKEN");
	exit(5);
} /* wait_for_quit() */

void pipeline_full(struct session_t *data)
{
	SHARED_STATS_INC(errors_pipeline_full);

	fdprintf(data->server, "QUIT\r\n");
	SAFE_CLOSE(data->server);

	spool_close(data);
	if (!IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ALWAYS))
		spool_remove(data);

#if PIPELINE_SIZE_MIN < 10
#error Invalid PIPELINE_SIZE_MIN, should be set at least to 10
#else
#define PIPE(x)	(data->pipeline[data->command_pos_server+(x)].cmd)
	log_action(LOG_DEBUG, "pipeline trace: %d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
		PIPE(0), PIPE(1), PIPE(2), PIPE(3), PIPE(4),
	       	PIPE(5), PIPE(6), PIPE(7), PIPE(8), PIPE(9));
#undef PIPE
#endif
	// TODO: a moze od razu rozlaczyc?
	response(data, ER(503,5,0), "%s %s\r\n", config.proxy_name, config.msg_pipeline_full);
	wait_for_quit(data, "%s", config.msg_pipeline_full);
	exit(5);
}


/*
 * polaczenie pass-thru
 * zestawia "tunel" pomiedzy serwerem i klientem, nie ingeruje w przesylane dane.
*/

void direct_proxy(struct session_t *data, char* cause)
	__attribute__ ((noreturn));

void direct_proxy(struct session_t *data, char* cause)
{
	fd_set rfds;
	struct timeval tv;
	int max_fd, size;
	int res;
	char buffer[config.buffer_size];


	CLEAR_TIMEOUT();
	log_action(LOG_DEBUG, "DIRECT:GOING cause=%s", cause);

	// deskryptor dla select-a
	max_fd = (data->client > data->server) ? data->client : data->server;

	SHARED_STATS_INC(requests_direct);
	SHARED_CONN_STATUS(state, CONN_DIRECT);

	for (;;) {
		if (force_finish) {
			res = LINE_CLOSED_ADMIN;
			break;
		}

		FD_ZERO(&rfds);
		FD_SET(data->client, &rfds);
		FD_SET(data->server, &rfds);
		tv.tv_sec = config.timeout_direct;
		tv.tv_usec = 0;

		if ((res = select(max_fd+1, &rfds, NULL, NULL, &tv)) == -1) {
			log_action(LOG_ERR, "select: %s", strerror(errno));
			continue;
		}

		// timeout
		if (res == 0) {
			res = LINE_CLOSED_TIMEOUT;
			break;
		}

		// dane od klienta
		if (FD_ISSET(data->client, &rfds)) {
			if ((size = read(data->client, buffer, sizeof(buffer))) == -1) {
				log_action(LOG_ERR, "direct:client:read error: %s", strerror(errno));
				res = LINE_ERROR;
				break;
			} else if (size == 0) {
				res = LINE_CLOSED;
				break;
			} else {
				data->cli_rx += size;
				SHARED_CONN_STATUS(cli_rx, data->cli_rx);
				write(data->server, buffer, size);
			}
		}

		// dane z serwera
		if (FD_ISSET(data->server, &rfds)) {
			if ((size = read(data->server, buffer, sizeof(buffer))) == -1) {
				log_action(LOG_ERR, "direct:server:read error: %s", strerror(errno));
				res = LINE_ERROR;
				break;
			} else if (size == 0) {
				res = LINE_CLOSED_SERVER;
				break;
			} else {
				data->srv_rx += size;
				SHARED_CONN_STATUS(srv_rx, data->srv_rx);
				write(data->client, buffer, size);
			}
		}

	}

	SAFE_CLOSE(data->client);
	SAFE_CLOSE(data->server);

	cleanup();

	log_action(LOG_NOTICE|LOG_ALWAYS, "CLOSE:DIRECT by=%s rcv=%d/%d, time=%" FORMAT_TIME_T ", src=%s, ident=%s",
		line_closed_cause(res), data->cli_rx, data->srv_rx, time(NULL)-data->start_time,
		data->origin_str, data->ident);
	exit(0);
} /* direct_proxy */


/*
 * 	logowanie adresow z naglowka
 *	zakladamy: line w postaci zakonczonej '\0'
*/

/*
 *	naglowek wiadomosci
*/

void prepare_nat_header(struct session_t *data)
{
//	char *buf_from, *buf_ident, *buf_with, *buf_abuse;
	char buf_from[128], buf_ident[16+IDENT_SIZE], buf_with[128], buf_abuse[128];

	if (config.nat_header_type == NAT_HEADER_TYPE_IP_ONLY) {
		data->xheader_size = asprintf(&data->xheader, "%s: %s\r\n", config.nat_header, inet_ntoa(data->origin.sin_addr));
		if (data->xheader_size == -1) {
			data->xheader = NULL;
			data->xheader_size = 0;
		}

		return;
	}

	snprintf(buf_from, sizeof(buf_from), "%s: from [%s]:%d ",
		config.nat_header, inet_ntoa(data->origin.sin_addr), ntohs(data->origin.sin_port));
	TERMINATE_STRING(buf_from);

	if (!EMPTY_STRING(data->ident)) {
		snprintf(buf_ident, sizeof(buf_ident), "[ident %s]\r\n", data->ident);
	} else {
		snprintf(buf_ident, sizeof(buf_ident), "[ident-empty]\r\n");
	}
	TERMINATE_STRING(buf_ident);

	snprintf(buf_with, sizeof(buf_with), "\tby %s with TPROXY id %" FORMAT_TIME_T ".%" FORMAT_PID_T "\r\n",
		config.proxy_name, data->start_time, getpid());
	TERMINATE_STRING(buf_with);

	if (!EMPTY_STRING(config.abuse)) {
		snprintf(buf_abuse, sizeof(buf_abuse), "\tabuse-to %s\r\n", config.abuse);
	} else {
		buf_abuse[0] = '\0';
	}
	TERMINATE_STRING(buf_abuse);

	data->xheader_size = asprintf(&data->xheader, "%s%s%s%s", buf_from, buf_ident, buf_with, buf_abuse);
	if (data->xheader_size == -1) {
		data->xheader = NULL;
		data->xheader_size = 0;
	}
} /* prepare_nat_header() */


/*
 * 	obsluga logowania mail from/rcpt to
*/


void destroy_mail_from(struct session_t *data)
{
	if (data->mail_from) {
		free(data->mail_from);
		data->mail_from = NULL;
	}
	data->mail_from_logged = 0;
} /* destroy_mail_from() */

void destroy_rcpt_to(struct session_t *data)
{
	int i;

	for (i=0; i<RCPTS_ONE_TIME; i++) {
		if (!data->rcpt_to[i]) continue;

		free(data->rcpt_to[i]);
		data->rcpt_to[i] = NULL;
	}

	data->rcpts = 0;
} /* destroy_rcpt_to() */

inline void destroy_addresses(struct session_t *data)
{
	destroy_mail_from(data);
	destroy_rcpt_to(data);
}

void flush_addresses(struct session_t *data)
{
	if ((!data->mail_from || data->mail_from_logged) && !data->rcpts) return;

	if (data->mail_from && !data->mail_from_logged) {
		if (!data->rcpts) {
			log_action(LOG_INFO|LOG_ALWAYS, "MAIL FROM <%s>", data->mail_from);
			data->mail_from_logged = 1;
			return;
		} else {
			log_action(LOG_INFO|LOG_ALWAYS, "MAIL FROM <%s> RCPT TO: %03d<%s>",
				data->mail_from, data->rcpt_to_code[0], data->rcpt_to[0]);
			data->mail_from_logged = 1;

			free(data->rcpt_to[0]);
			data->rcpt_to[0] = data->rcpt_to[1];
			data->rcpt_to_code[0] = data->rcpt_to_code[1];
			data->rcpt_to[1] = NULL;

			data->rcpts--;
			return;
		}
	}

	// data->rcpts > 0
	if (data->rcpts == 1) {
		log_action(LOG_INFO|LOG_ALWAYS, "RCPT TO: %03d<%s>",
			data->rcpt_to_code[0], data->rcpt_to[0]);
	} else {
		log_action(LOG_INFO|LOG_ALWAYS, "RCPT TO: %03d<%s>, %03d<%s>",
			data->rcpt_to_code[0], data->rcpt_to[0],
			data->rcpt_to_code[1], data->rcpt_to[1]);
	}

//	destroy_addresses(data);
	destroy_rcpt_to(data);
} /* flush_addresses() */

// email is malloc-ed
void new_mail_from(struct session_t *data, char *email, int code)
{
	char *tmp;
	int accepted = (code == 250);

	if (IS_FLAG_SET(config.log_mail_from, LOG_MAIL_BASE64)) {
		tmp = strdup(md5_string_base64(email));
		free(email);
		email = tmp;
	} else {
		untaint(email, 0);	// 20101014
	}

	if (data->mail_from) free(data->mail_from);
	data->mail_from = email;
	data->mail_from_logged = 0;

	if (IS_FLAG_CLEARED(config.log_mail_from, (accepted ? LOG_MAIL_ACCEPTED : LOG_MAIL_REJECTED)))
		return;

	if (!accepted) {
		log_action(LOG_NOTICE|LOG_ALWAYS, "MAIL FROM <%s> rejected [%d]", email, code);
//		free(email);
		return;
	}
} /* net_mail_from() */

// email is malloc-ed
void add_rcpt_to(struct session_t *data, char *email, int code)
{
	char *tmp;

	if (IS_FLAG_CLEARED(config.log_rcpt_to, (code == 250 ? LOG_MAIL_ACCEPTED : LOG_MAIL_REJECTED))) {
		free(email);
		return;
	}

	if (IS_FLAG_SET(config.log_rcpt_to, LOG_MAIL_BASE64)) {
		tmp = strdup(md5_string_base64(email));
		free(email);
		email = tmp;
	} else {
		untaint(email, 0);	// 20101014
	}

	data->rcpt_to[data->rcpts] = email;
	data->rcpt_to_code[data->rcpts] = code;
	data->rcpts++;

	if ((data->rcpts >= RCPTS_ONE_TIME) || (data->mail_from && !data->mail_from_logged))
		flush_addresses(data);
} /* add_rcpt_to() */


/*
 * 	funkcje obslugi sesji
*/

void transaction_reset(struct session_t *data)
{
	data->data_used = 0;
	data->bdat_used = 0;
	data->bdat_togo = 0;
	data->bdat_last = 0;

	data->size = 0;
	data->header_size = 0;
	data->extra_size = 0;

	destroy_addresses(data);
} /* transaction_reset() */

typedef enum {
	H_OK = 0,
	H_STOLEN,
	H_BINARY,
	H_BINARY_STOLEN,
} handle_status_t;

handle_status_t handle_data(struct session_t *data)
{
	int res;

	if ((config.auth_require == AUTH_REQUIRE_NO) || IS_FLAG_SET(data->auth, AUTH_FLAG_ACCEPTED) ||
			((config.auth_require == AUTH_REQUIRE_IFSUPPORTED) && !IS_FLAG_SET(data->auth, AUTH_FLAG_SUPPORTED))) {
		if (ratelimit_uint(data, RATELIMIT_INT_MESSAGES, 1)) {
			// TODO: lock?
			response(data, ER(552,3,2), "%s %s\r\n", config.proxy_name,
				config.msg_ratelimit_messages);
			return H_STOLEN;
		}
		log_action(LOG_DEBUG, "DATA:REQUEST");
		if (spool_create(data) != 0) {
			res = errno;
			fdprintf(data->server, "QUIT\r\n");
			SAFE_CLOSE(data->server);

			response(data, ER(451,3,1), "%s %s: %s\r\n", config.proxy_name,
				config.msg_spool_open_fail, strerror(res));
			wait_for_quit(data, "%s %s: %s", config.proxy_name,
				config.msg_spool_open_fail, strerror(res));
			exit(5);
		}
		// possibly receives "go ahead" [354] response
		queue_command(COMMAND_DATA, data);
		// pseudo-command, receives transaction ack [250]
		queue_command(COMMAND_DATA_ACK, data);
	} else {
		SHARED_STATS_INC(noauths);
		log_action(LOG_INFO, "DATA:AUTH_REQUIRED");
		response(data, ER(530,7,1), "%s %s\r\n", config.proxy_name, config.msg_auth_required);
		return H_STOLEN;
#if 0
		// 20071024: czy aby napewno?
		queue_command(COMMAND_NONE, data);
		fdprintf(data->server, "NOOP\r\n");
#endif
	}

	return H_OK;
}

handle_status_t handle_bdat(struct session_t *data, char* buffer)
{
	int chunk_size, last_chunk;
	char tmp[64];

	strncpy(tmp, buffer, sizeof(tmp));
	TERMINATE_STRING(tmp);
	upcase(tmp);

	if (sscanf(tmp, "BDAT %u LAST", &chunk_size) == 1) {
		last_chunk = 1;
	} else if (sscanf(tmp, "BDAT %d", &chunk_size) == 1) {
		last_chunk = 0;
	} else {
		chunk_size = last_chunk = 0;
	}

	if (data->chunking) {
		log_action(LOG_DEBUG, "BDAT:REQUEST %d %s", chunk_size, last_chunk ? "LAST" : "");
		// TODO: "BDAT chunk_size LAST" => "BDAT chunk_size", "BDAT 0 LAST"/"QUIT"
		// stolen = 1;
		data->bdat_togo = chunk_size;
		data->bdat_last = last_chunk;

		if (last_chunk) {
			fdprintf(data->server, "BDAT %u\r\n", chunk_size);
//			queue_commandp(COMMAND_BDAT_PRELAST, data, (pipeline_parm_t) chunk_size, (pipeline_parm_t) last_chunk);
//			queue_commandp(COMMAND_BDAT_LAST, data, (pipeline_parm_t) chunk_size, (pipeline_parm_t) last_chunk);
			queue_commandp(COMMAND_BDAT, data, arg_t_i(chunk_size), arg_t_i(last_chunk));
			return H_BINARY_STOLEN;
		} else {
			queue_commandp(COMMAND_BDAT, data, arg_t_i(chunk_size), arg_t_i(last_chunk));
			return H_BINARY;
		}
	} else {
		log_action(LOG_DEBUG, "BDAT:FILTERED src=%s, ident=%s", data->origin_str, data->ident);
		response(data, ER(502,5,2), "%s %s\r\n", config.proxy_name, config.msg_unimpl_command);
		return H_STOLEN;
#if 0
		// 20071024: czy aby napewno?
		buffer[3] = '*';
		queue_command(COMMAND_OTHER, data);
#endif
	}
}

handle_status_t handle_rcpt_to(struct session_t *data, char *buffer)
{
	char *param_tmp;

	if (ratelimit_uint(data, RATELIMIT_INT_RECIPIENTS, 1)) {
		// lock?
		response(data, ER(552,3,2), "%s %s\r\n", config.proxy_name,
			config.msg_ratelimit_rcptto);
		return H_STOLEN;
	}

	param_tmp = alloc_msg_mail(buffer+8, config.email_length);

	// verb_rcpt_to();
#ifdef USE_REGEX
	if (!IS_FLAG_SET(config.auth_skip, AUTH_SKIP_REGEX) && !regex_check_rcpt_to(param_tmp)) {
		// TODO: untaint param_tmp
		log_action(LOG_DEBUG, "REGEX:REJECT rcpt=%s", param_tmp);
		found(data, LOCK_ON_REGEX, FOUND_REGEX_RCPT_TO, "REGEX_RCPT_TO");

		SHARED_STATS_INC(regex);
		fdprintf(data->server, "QUIT\r\n");
		SAFE_CLOSE(data->server);
		response(data, ER(550,7,1), "%s %s\r\n", config.proxy_name, config.msg_regex_rcpt_to);
		wait_for_quit(data, "%s", config.msg_regex_rcpt_to);
	}
#endif
	queue_commandp(COMMAND_RCPT, data, arg_t_s(param_tmp), arg_t_s(NULL));
	return H_OK;
}

handle_status_t handle_mail_from(struct session_t *data, char* buffer)
{
	int res;

	char* param_tmp = alloc_msg_mail(buffer+10, config.email_length);
	// verb_mail_from();

	if (ratelimit_string(data, RATELIMIT_STRING_MAILFROM, param_tmp)) {
		fdprintf(data->server, "QUIT\r\n");
		SAFE_CLOSE(data->server);
		response(data, ER(550,7,1), "%s %s\r\n", config.proxy_name, config.msg_ratelimit_mailfrom);
		wait_for_quit(data, "%s", config.msg_ratelimit_mailfrom);
	}

#ifdef USE_REGEX
	if (!IS_FLAG_SET(config.auth_skip, AUTH_SKIP_REGEX) && !regex_check_mail_from(param_tmp)) {
		// TODO: untaint param_tmp
		log_action(LOG_DEBUG, "REGEX:REJECT mail=%s", param_tmp);
		found(data, LOCK_ON_REGEX, FOUND_REGEX_MAIL_FROM, "REGEX_MAIL_FROM");

		SHARED_STATS_INC(regex);
		fdprintf(data->server, "QUIT\r\n");
		SAFE_CLOSE(data->server);
		response(data, ER(550,7,1), "%s %s\r\n", config.proxy_name, config.msg_regex_mail_from);
		wait_for_quit(data, "%s", config.msg_regex_mail_from);
	}
#endif
	if (config.dnsbl && IS_FLAG_SET(config.auth_skip, AUTH_SKIP_DNSBL) && !IS_FLAG_SET(data->auth, AUTH_FLAG_ACCEPTED)) {
		SHARED_CONN_STATUS(state, CONN_DNSBL);
		res = dnsbl_check(data);
		switch (res) {
			case 0: /* OK */
				break;
			case -1: /* error */
			case 1:	/* found in dnsbl */
				SHARED_STATS_INC(rejects_dnsbl);

				fdprintf(data->server, "QUIT\r\n");
				SAFE_CLOSE(data->server);

				log_action(LOG_DEBUG, "DNSBL:REJECT MAIL");
				found(data, LOCK_ON_DNSBL, FOUND_DNSBL, "DNSBL");
				response(data, ER(550,7,1), "%s %s: %s\r\n", config.proxy_name, config.msg_dnsdb_reject,
					!EMPTY_STRING(data->message) ? data->message : "-");
				wait_for_quit(data, "%s", config.msg_dnsdb_reject);
				exit(0);
		}
		SHARED_CONN_STATUS(state, CONN_PRE);
	}

#ifdef USE_SPF
	if (config.spf) {
		res = spf_check(data, param_tmp);
		if (!config.spf_log_only) {
			switch (res) {
				case SPF_PASS:
				case SPF_NONE:
				case SPF_SKIP:
					break;
				case SPF_FAIL:
					SHARED_STATS_INC(spf);

					fdprintf(data->server, "QUIT\r\n");
					SAFE_CLOSE(data->server);

					log_action(LOG_DEBUG, "SPF:REJECT");
					found(data, LOCK_ON_SPF, FOUND_SPF, "SPF");
					response(data, ER(550,7,1), "%s %s: %s\r\n", config.proxy_name, config.msg_spf_reject,
						!EMPTY_STRING(data->message) ? data->message : "-");
					wait_for_quit(data, "%s", config.msg_spf_reject);
					exit(0);
				case SPF_ERROR:
					// if (!config.ignore_errors)
					log_action(LOG_DEBUG, "SPF:ERROR");
					break;
				case SPF_INVALID:
				default:
					log_action(LOG_DEBUG, "!BUG!invalid SPF response: %d", res);
					break;
			}
		}
	}
#endif
	// check_verb(COMMAND_MAIL, param_tmp)
	queue_commandp(COMMAND_MAIL, data, arg_t_s(param_tmp), arg_t_s(NULL));

	return H_OK;
}


handle_status_t handle_helo(struct session_t *data, char* buffer)
{
	FREE_NULL(data->helo);
	data->helo = strdup(buffer+5);
	untaint(data->helo, 0);
	// verb_helo()

#ifdef USE_REGEX
	// no helo after AUTH, so no need to check auth_skip
	if (!regex_check_helo(data->helo)) {
		log_action(LOG_DEBUG, "REGEX:REJECT src=%s, ident=%s, helo=%s",
			data->origin_str, data->ident, data->helo);
		found(data, LOCK_ON_REGEX, FOUND_REGEX_HELO_EHLO, "REGEX_HELO");

		SHARED_STATS_INC(regex);
		fdprintf(data->server, "QUIT\r\n");
		SAFE_CLOSE(data->server);
		response(data, ER(550,7,1), "%s %s\r\n", config.proxy_name, config.msg_regex_helo);
		wait_for_quit(data, "%s", config.msg_regex_helo);
	}
#endif
	if (ratelimit_string(data, RATELIMIT_STRING_HELO, data->helo)) {
		fdprintf(data->server, "QUIT\r\n");
		SAFE_CLOSE(data->server);
		response(data, ER(550,7,1), "%s %s\r\n", config.proxy_name, config.msg_ratelimit_helo);
		wait_for_quit(data, "%s", config.msg_ratelimit_helo);
	}

	// check_verb(COMMAND_HELO, buffer+5)
	queue_commandp(buffer[0] == 'H' ? COMMAND_HELO : COMMAND_EHLO, data, arg_t_s(strndup(buffer+5, HELO_LENGTH)), arg_t_s(NULL));

	return H_OK;
}

handle_status_t handle_xclient(struct session_t *data, char* buffer)
{
	// check_verb(COMMAND_XCLIENT)
	if (data->mode == MODE_FIXED_XCLIENT) {
		log_action(LOG_WARNING, "XCLIENT:FILTERED src=%s, ident=%s", data->origin_str, data->ident);
		response(data, ER(502,5,2), "%s %s\r\n", config.proxy_name, config.msg_unimpl_command);
		return H_STOLEN;
	} else {
		queue_command(COMMAND_XCLIENT, data);
		return H_OK;
	}
}



handle_status_t handle_data_finished(struct session_t *data, char* buffer)
{
	char *msg;

	spool_close(data);
	// msg_body_done()
	msg = spool_scan(data);
	if (!EMPTY_STRING(msg)) {
		SAFE_CLOSE(data->server);

		response(data, ER(550,7,1), "%s %s\r\n", config.proxy_name, msg);
		wait_for_quit(data, "%s", msg);
		exit(5);
	}

	// we check for lockfile again, to eliminate flood at the very beginning
	if (lockfile_present(data)) {
		SAFE_CLOSE(data->server);
		// and again: no need to be nice, chop it off
		response(data, ER(451, 4, 0), "%s %s\r\n", config.proxy_name, config.msg_virus_locked);
		SAFE_CLOSE(data->client);
		stats->rejects_lock++;
		exit(5);
	}

	// ratelimit_uint(data, RATELIMIT_INT_BYTES, data->size);
	SHARED_CONN_STATUS(state, CONN_POST);

	return H_OK;
}


line_status client_callback(char *buffer, char *pos, int size, void *ptr)
{
	struct session_t *data = ptr;
	char *replace_pos, replace_char;
	int res = 0;
	handle_status_t h_status = H_OK;
	line_status ret_code = LINE_OK;

	// nie zakonczona linia => nic sie nie da zrobic
	if (!pos) goto write_ok;

	// earlytalker: client sent something before MTA greeting arrived; bad client!
//	if (config.earlytalker && (config.mode != MODE_FIXED_XCLIENT) && (data->pipeline[data->command_pos_client].cmd == COMMAND_GREETING)) {
	if (config.earlytalker && (config.mode != MODE_FIXED_XCLIENT) && (data->srv_rx == 0)) {
		SAFE_CLOSE(data->server);
		log_action(LOG_DEBUG, "FOUND:EARLYTALK src=%s ident=%s", data->origin_str, data->ident);
//		log_action(LOG_INFO, "CLOSE:EARLYTALK");
		found(data, LOCK_ON_EARLYTALK, FOUND_EARLYTALK, "EARLYTALK");
		SHARED_STATS_INC(earlytalk);
		fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_earlytalker);
		SAFE_CLOSE(data->client);
		cleanup_exit(1);
	}

	save_remove_crlf(buffer, pos, &replace_pos, &replace_char);
//	if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%d] => %s\n", getpid(), buffer);

	if (data->data_going == GOING_NONE) {
		if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%" FORMAT_PID_T "] <= %s\n", getpid(), buffer);

		if (strcasecmp(buffer, "DATA") == 0 || strncasecmp(buffer, "DATA ", 5) == 0) {
			h_status = handle_data(data);
		} else if (strncasecmp(buffer, "XEXCH50 ", 8) == 0) {
			log_action(LOG_DEBUG, "XEXCH50:FILTERED src=%s, ident=%s", data->origin_str, data->ident);
			response(data, ER(502,5,2), "%s %s\r\n", config.proxy_name, config.msg_unimpl_command);
			h_status = H_STOLEN;
		} else if (strncasecmp(buffer, "BDAT ", 5) == 0) {
			h_status = handle_bdat(data, buffer);
		} else if (strcasecmp(buffer, "STARTTLS") == 0 || strncasecmp(buffer, "STARTTLS ", 9) == 0) {
			if (config.forbid_starttls) {
				log_action(LOG_DEBUG, "STARTTLS:FILTERED src=%s, ident=%s", data->origin_str, data->ident);
				response(data, ER(502,5,2), "%s %s\r\n", config.proxy_name, config.msg_unimpl_command);
				h_status = H_STOLEN;
			} else {
				// check_starttls(param_tmp)
				log_action(LOG_DEBUG, "STARTTLS:REQUEST");
				queue_command(COMMAND_STARTTLS, data);
			}
		} else if (strcasecmp(buffer, "RSET") == 0 || strncasecmp(buffer, "RSET ", 5) == 0) {
			queue_command(COMMAND_RSET, data);
		} else if (strcasecmp(buffer, "QUIT") == 0 || strncasecmp(buffer, "QUIT ", 5) == 0) {
			queue_command(COMMAND_QUIT, data);
		} else if (strncasecmp(buffer, "AUTH ", 5) == 0) {
			queue_command(COMMAND_AUTH, data);
		} else if (strncasecmp(buffer, "RCPT TO:", 8) == 0) {
			h_status = handle_rcpt_to(data, buffer);
		} else if (strncasecmp(buffer, "MAIL FROM:", 10) == 0) {
			h_status = handle_mail_from(data, buffer);
		} else if (strncasecmp(buffer, "HELO ", 5) == 0 || strncasecmp(buffer, "EHLO ", 5) == 0) {
			h_status = handle_helo(data, buffer);
		} else if (strncasecmp(buffer, "XCLIENT ", 8) == 0) {
			h_status = handle_xclient(data, buffer);
		} else {
			queue_command(COMMAND_OTHER, data);
		}
	} else if (data->data_going == GOING_AUTH) {
		data->data_going = GOING_NONE;
		queue_command(COMMAND_AUTH, data);
	} else {
		if (strcmp(buffer, ".") == 0) {
			if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%" FORMAT_PID_T "] <= %s\n", getpid(), buffer);
			h_status = handle_data_finished(data, buffer);
		} else {
			if (data->data_going == GOING_HEADER) {
				// ... header
				if (buffer[0] == '\0') {
					// empty line => message header complete
					data->data_going = GOING_BODY;
					data->header_size = data->size;
					// msg_header_done()
				}
			}

//			if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "<#  %s\n", buffer);
			restore_crlf(buffer, pos, &replace_pos, &replace_char);
			if (buffer[0] == '.') {
				// wycinamy pierwsza kropke [channel transparency]
				spool_write(data, buffer+1, size-1);
			} else {
				spool_write(data, buffer, size);
			}

			if (config.size_limit && (data->size > config.size_limit)) {
				SAFE_CLOSE(data->server);
				spool_remove(data);
				response(data, ER(552, 3, 4), "%s %s\r\n", config.proxy_name, config.msg_size_limit);
				wait_for_quit(data, "%s", config.msg_size_limit);
				exit(5);
			}
		}
	}

	switch (h_status) {
	case H_OK:
		break;
	case H_STOLEN:	// command stolen from command stream, don't send it to server
		return ret_code;
	case H_BINARY:	// mode switch to binary (BDAT)
		ret_code = LINE_BINARY;
		break;
	case H_BINARY_STOLEN:
		return LINE_BINARY;
	}

	restore_crlf(buffer, pos, &replace_pos, &replace_char);

write_ok:
	for (;;) {
		if (timedout) {
			CLEAR_TIMEOUT();
			errno = ETIMEDOUT;
			return LINE_CLOSED;
		}
		if ((res = write(data->server, buffer, size)) == -1) {
			if (errno == EINTR) continue;
#ifdef SILENT_ECONNRESET
			if (errno == ECONNRESET) return LINE_CLOSED;
#endif
			log_action(LOG_ERR, "client:write(%d) error: %s", size, strerror(errno));
			return LINE_CLOSED;
		}

		if (res == 0) {
			log_action(LOG_ERR, "client:write(%d) returned 0 (connection lost)", size);
			return LINE_CLOSED;
		}

		break;
	}

	return ret_code;
} /* client_callback() */

line_status server_callback(char *buffer, char *pos, int size, void *ptr)
{
	char *replace_pos, replace_char;
	struct session_t *data = ptr;
	smtp_command_t command;
	pipeline_arg_t parm1, parm2;
	int res;
	int code;		// numeric response code
	int cont;		// response continues on next line
	char *direct = NULL;	// enter direct proxy mode
	int stolen = 0;
	int ret_code = LINE_OK;	// function return code


	// dluga linia/krotka linia => nie ma co sprawdzac
	// jesli nieprawidlowa odpowiedz z serwera to tez nie ma co robic
	if (!pos || size<3 || (code = resp_code(buffer)) == -1) goto write_ok;

	// status bedzie kontynuowany?
	cont = ((size > 3) && (buffer[3] == '-'));

	// co nas czeka
	command = poll_commandp(data, &parm1, &parm2);
//	if (foreground) log_action(LOG_DEBUG, "POLL:COMMAND %d", command);

#ifdef FILTER_CHUNKING
	// paskudny hack, length("250 CHUNKING")=12[+crlf]
	if (command == COMMAND_EHLO && size>=12 && code == 250) {
		save_remove_crlf(buffer, pos, &replace_pos, &replace_char);

		if (strcasecmp(buffer+4, "CHUNKING") == 0) {
			log_action(LOG_DEBUG, "ESMTP CHUNKING extension filtered-out dst=%s:%d",
				data->target_str, ntohs(data->target.sin_port));
			buffer[7] = '*';
		} else if (strcasecmp(buffer+4, "BINARYMIME") == 0) {
			log_action(LOG_DEBUG, "ESMTP BINARYMIME extension filtered-out dst=%s:%d",
				data->target_str, ntohs(data->target.sin_port));
			buffer[7] = '*';
		} else if (strcasecmp(buffer+4, "XEXCH50") == 0) {
			log_action(LOG_DEBUG, "ESMTP XEXCH50 extension filtered-out dst=%s:%d",
				data->target_str, ntohs(data->target.sin_port));
			buffer[7] = '*';
		}

		restore_crlf(buffer, pos, &replace_pos, &replace_char);
	}
#else
#warning CHUNKING support possibly broken! use -DFILTER_CHUNKING to filter this extension
#endif

	// przygotowania
	save_remove_crlf(buffer, pos, &replace_pos, &replace_char);
	if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%" FORMAT_PID_T "] => %s\n", getpid(), buffer);

	// process both continued and ending responses
	switch (command) {
		case COMMAND_EHLO:	// SMTP service extensions
			if (code == 250) {
				if (strcasecmp(buffer+4, "ENHANCEDSTATUSCODES") == 0) {
					data->enhancedstatuscodes = 1;
					log_action(LOG_DEBUG, "ESMTP ENHANCEDSTATUSCODES supported dst=%s:%d",
						data->target_str, ntohs(data->target.sin_port));
				} else if (strncasecmp(buffer+4, "AUTH ", 5) == 0) {
					data->auth |= AUTH_FLAG_SUPPORTED;
					SHARED_CONN_STATUS(auth, data->auth);
					log_action(LOG_DEBUG, "ESMTP AUTH supported dst=%s:%d",
						data->target_str, ntohs(data->target.sin_port));
				} else if (strcasecmp(buffer+4, "CHUNKING") == 0) {
					data->chunking = 1;
					log_action(LOG_DEBUG, "ESMTP CHUNKING supported dst=%s:%d",
						data->target_str, ntohs(data->target.sin_port));
				} else if (strncasecmp(buffer+4, "XCLIENT ", 8) == 0) {
					data->xclient = 1;
					if (data->mode == MODE_FIXED_XCLIENT) {
						// filter XCLIENT: stolen=1
						buffer[7] = '*';
					} else {
						log_action(LOG_DEBUG, "ESMTP XCLIENT supported dst=%s:%d",
							data->target_str, ntohs(data->target.sin_port));
					}
				}
			}
		default:
			break;
	}

	// odpowiedz nie zakonczona nas w tym momencie nie interesuje
	if (cont) goto restore_write_ok;

#ifdef TODO
	if (config.code5xx && code >= 500 && code <= 599) {
		if (IS_FLAG_SET(config.code5xx, CODE_5XX_LOG)
			log_action(...)
		if (IS_FLAG_SET(config.code5xx, CODE_5XX_REJECT)) {
			fdprintf(data->server, "QUIT\r\n");
			SAFE_CLOSE(data->server);
			// 5xx smtp-gated takeover, server said: 5xx ...
			wait_for_quit();
			exit(5);
		}
	}
#endif

	// odpowiedz nie bedzie kontynuowana
	if (command != COMMAND_NONE) dequeue_command(data);

	// pipeline: liczenie odpowiedzi,
	// STARTTLS,DATA jest juz synchronizowane
	switch (command) {
		case COMMAND_DATA:
			if (code == 354) {
				data->data_used = 1;
				flush_addresses(data);
				data->data_going = GOING_HEADER;
				data->transaction++;

				SHARED_CONN_STATUS(transaction, data->transaction);
				SHARED_CONN_STATUS(state, CONN_DATA);

				if (config.nat_header_type && data->xheader) fdprintf(data->server, "%s", data->xheader);
				log_action(LOG_DEBUG, "DATA:GOING");
			} else {
				destroy_addresses(data);	// 20050311
				spool_remove(data);
				data->data_going = GOING_NONE;
				// dequeue pseudo-command COMMAND_DATA_ACK
				// there won't be any ack cause it's already failed
				dequeue_command(data);
				log_action(LOG_DEBUG, "DATA:CANCELLED [%d]", code);
			}
			break;

		case COMMAND_DATA_ACK:
			transaction_reset(data);
			data->data_going = GOING_NONE;
//			SHARED_CONN_STATUS(state, CONN_ACK);
			log_action(LOG_DEBUG, "DATA:FINISHED [%d]", code);
			break;

		case COMMAND_BDAT:
			if (code == 250) {
				flush_addresses(data);
				log_action(LOG_DEBUG, "BDAT:CHUNK ok [%d] %s", (int) parm1.i, parm2.i ? "LAST" : "");
				if (!data->bdat_used) {
					if (data->data_used) {}
					data->bdat_used = 1;
					// tymczasowe rozwiazanie
					flush_buffers(data);
					log_action(LOG_DEBUG, "BDAT:DIRECT");
					direct = "bdat";
					break;
					// TODO: inject for BDAT!
					//if (config.nat_header_type && data->xheader) inject_nat_header(data);
				}

				// BDAT last
				if (parm2.i) {


				}
			} else {
				destroy_addresses(data);	// 20050311
				log_action(LOG_DEBUG, "BDAT:CHUNK rejected [%d]", code);
				data->bdat_togo = 0;
				data->bdat_last = 0;
//				data->bdat_used = 0;	// TODO: napewno?
			}
			break;

		case COMMAND_MAIL:
			transaction_reset(data);
//			ack = (code == 250);
			new_mail_from(data, parm1.s, code);
			if (code >= 500 && code <= 599) {
#warning TEST:RATELIMIT_MAILFROM_REJECTS
				if (ratelimit_uint(data, RATELIMIT_INT_MAILFROM_REJECTS, 1)) {
					found(data, LOCK_ON_RATELIMIT, FOUND_RATELIMIT_MAILFROM_REJECTS, "RATELIMIT_MAILFROM_REJECTS");
					SHARED_STATS_INC(rejects_ratelimit);
					fdprintf(data->server, "QUIT\r\n");
					SAFE_CLOSE(data->server);
					response(data, ER(550,7,1), "%s %s\r\n", config.proxy_name, config.msg_ratelimit_mailfrom_rejects);
					wait_for_quit(data, "%s", config.msg_ratelimit_mailfrom_rejects);
				}
			}
			parm1.s = NULL;
			break;

		case COMMAND_RCPT:
			add_rcpt_to(data, parm1.s, code);
			if (code == 250) {
				data->rcpts_total++;
			} else if (code >= 500 && code <= 599) {
#warning TEST:RATELIMIT_RCPTTO_REJECTS
				if (ratelimit_uint(data, RATELIMIT_INT_RCPTTO_REJECTS, 1)) {
					found(data, LOCK_ON_RATELIMIT, FOUND_RATELIMIT_RCPTTO_REJECTS, "RATELIMIT_RCPTTO_REJECTS");
					SHARED_STATS_INC(rejects_ratelimit);
					fdprintf(data->server, "QUIT\r\n");
					SAFE_CLOSE(data->server);
					response(data, ER(550,7,1), "%s %s\r\n", config.proxy_name, config.msg_ratelimit_rcptto_rejects);
					wait_for_quit(data, "%s", config.msg_ratelimit_rcptto_rejects);
				}
			}
			parm1.s = NULL;
			break;

		case COMMAND_STARTTLS:
			if (code == 220) {
				destroy_addresses(data);
				if (!IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ALWAYS))
					spool_remove(data);
				direct = "starttls";
			} else {
				log_action(LOG_DEBUG, "DIRECT:CANCELLED cause=starttls code=%d", code);
			}
			break;

		case COMMAND_AUTH:
			if (code == 235) {
				log_action(LOG_DEBUG, "AUTH:ACCEPT src=%s, ident=%s",
					data->origin_str, data->ident);
				data->auth |= AUTH_FLAG_ACCEPTED;
				SHARED_CONN_STATUS(auth, data->auth);
				SHARED_STATS_INC(auth_accepts);
#warning TODO:AUTH_SKIP_DIRECT
				if (IS_FLAG_SET(config.auth_skip, AUTH_SKIP_DIRECT)) {
					log_action(LOG_DEBUG, "DIRECT:GOING cause=auth");
					direct = "auth";
				}
			} else if (code == 334) {
				log_action(LOG_DEBUG, "AUTH:CHALLENGE src=%s, ident=%s",
					data->origin_str, data->ident);
				data->data_going = GOING_AUTH;
			} else {
				// ratelimit_uint(data, RATELIMIT_INT_AUTH_REJECTS, 1);
				log_action(LOG_WARNING, "AUTH:REJECT [%d] src=%s, ident=%s",
					code, data->origin_str, data->ident);
				data->auth |= AUTH_FLAG_REJECTED;
				SHARED_CONN_STATUS(auth, data->auth);
				SHARED_STATS_INC(auth_rejects);
			}
			break;

		case COMMAND_RSET:
			transaction_reset(data);
			SHARED_CONN_STATUS(state, CONN_RSET);
			log_action(LOG_DEBUG, "RSET [%d]", code);
			break;

		case COMMAND_XCLIENT:
			log_action(LOG_DEBUG, "XCLIENT [%d]", code);
			break;

		case COMMAND_HELO:
		case COMMAND_EHLO:
			transaction_reset(data);
			SHARED_CONN_STATUS(state, CONN_HELO);

			if (config.log_helo) {
				log_action(LOG_INFO|LOG_ALWAYS, "%s src=%s, ident=%s, helo=%s\n",
					(command == COMMAND_EHLO) ? "EHLO" : "HELO",
					data->origin_str, data->ident, data->helo);
			}
			break;

		case COMMAND_GREETING:
		case COMMAND_OTHER:
			break;

		default:
			break;
	}

restore_write_ok:
	restore_crlf(buffer, pos, &replace_pos, &replace_char);

	if (stolen)
		return ret_code;

write_ok:
	for (;;) {
		if (timedout) {
			CLEAR_TIMEOUT();
			errno = ETIMEDOUT;
			return LINE_CLOSED;
		}
		if ((res = write(data->client, buffer, size)) == -1) {
			if (errno == EINTR) continue;
#ifdef SILENT_ECONNRESET
			if (errno == ECONNRESET) return LINE_CLOSED;
#endif
			log_action(LOG_ERR, "server:write(%d) error: %s", size, strerror(errno));
			return LINE_CLOSED;
		}

		if (res == 0) {
			log_action(LOG_ERR, "server:write(%d) returned 0 (connection lost)", size);
			return LINE_CLOSED;
		}

		break;
	}

	if (direct) {
		direct_proxy(data, direct);
		exit(0);
	}

	return ret_code;
} /* server_callback() */


void session_free(struct session_t *data)
{
	FREE_NULL(data->cli_buf);
	FREE_NULL(data->srv_buf);
	FREE_NULL(data->pipeline);

	FREE_NULL(data->helo);
	FREE_NULL(data->xheader);
	FREE_NULL(data->spool_name);
	FREE_NULL(data->lockfile);
	FREE_NULL(data->virus_name);
	destroy_addresses(data);
	FREE_NULL(data->message);
	ratelimit_done(data);
}

void session_init_1(struct session_t *data, int client, struct sockaddr_in origin)
{
	memset(data, 0, sizeof(struct session_t));

	switch (config.mode) {
		case MODE_TPROXY_OR_NETFILTER:
			data->mode = is_routable(origin.sin_addr.s_addr) ? MODE_TPROXY : MODE_NETFILTER;
			break;
		default:
			data->mode = config.mode;
	}

	data->client = client;
	data->server = -1;
	data->origin = origin;
	// adres zrodlowy (tekst)
	snprintf(data->origin_str, sizeof(data->origin_str), "%s", inet_ntoa(data->origin.sin_addr));
	TERMINATE_STRING(data->origin_str);
	data->spool_fd = -1;
	data->start_time = time(NULL);
	data->rate_fd = -1;

	// utworz nazwe lockfile, jesli nie trzeba do tego identa
	switch (data->mode) {
		case MODE_FIXED:
		case MODE_FIXED_XCLIENT:
		case MODE_GETSOCKNAME:
		case MODE_XRELAY:
		case MODE_NETFILTER:
		case MODE_IPFW:
		case MODE_IPFILTER:
		case MODE_TPROXY:
		case MODE_PF:
			if (asprintf(&data->lockfile, "%s/%s", config.lock_path, data->origin_str) == -1)
				data->lockfile = NULL;
			break;
		case MODE_REMOTE:
		case MODE_REMOTE_UDP:
		default:
			break;
	}
} /* session_init_1() */

void session_init_2(struct session_t *data)
{
	int res;
	socklen_t len;

	if ((data->cli_buf = malloc(config.buffer_size)) == NULL) {
		goto no_mem;
	}
	if ((data->srv_buf = malloc(config.buffer_size)) == NULL) {
		goto no_mem;
	}

	// we should remember pipeline_size, because config.pipeline_size may change due to config reload
	data->pipeline_size = config.pipeline_size;
	if ((data->pipeline = malloc(data->pipeline_size * sizeof(struct pipeline_t))) == NULL) {
		goto no_mem;
	}

	// nazwa pliku spool-a
	if (asprintf(&data->spool_name, "%s/%" FORMAT_TIME_T ".%" FORMAT_PID_T, config.spool_path,
			data->start_time, getpid()) == -1) {
		data->spool_name = NULL;
		if (!config.ignore_errors) {
			session_free(data);
			helo(data->client);
			wait_for_quit(data, "%s", config.msg_spool_problem);
			exit(5);
		}
	}

	// adres lokalny potrzebny do ident-a
	len = sizeof(data->local);
	if (getsockname(data->client, (struct sockaddr *) &data->local, &len) != 0) {
		res = errno;
		session_free(data);
		helo(data->client);
		wait_for_quit(data, "%s: %s", config.msg_lookup_failed, strerror(res));
		exit(5);
	}
#if 0
	snprintf(data->local_str, sizeof(data->local_str), "%s", inet_ntoa(data->local.sin_addr));
	TERMINATE_STRINT(data->local_str);
#endif

	return;

no_mem:
	session_free(data);

	helo(data->client);
	wait_for_quit(data, "%s", config.msg_nomem);
	exit(5);
} /* session_init_2() */




int target_connect(struct session_t *data)
{
	int res;
	struct sockaddr_in src;


	SHARED_CONN_STATUS(dst, SIN_TO_UINT32(data->target.sin_addr));
	SHARED_CONN_STATUS(state, CONN_CONNECT);

	inet_aton(config.outgoing_addr, &src.sin_addr);
	SET_TIMEOUT(config.timeout_connect);

	switch (data->mode) {
		case MODE_TPROXY:
#ifdef USE_NAT_TPROXY
			// regain root privileges to apply IP_TRANSPARENT
			if (elevate_privileges() != 0) {
				fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_connect_failed);
				SAFE_CLOSE(data->client);
				exit(0);
			}
			data->server = connect_host_from_port(data->target, ntohs(data->target.sin_port), data->origin, ARRAY(int, SO_REUSEADDR, 0), ARRAY(int, IP_TRANSPARENT, 0));
			res = errno;

			// drop privileges entirely, not needed anymore
			if (drop_privileges() != 0) {
				SAFE_CLOSE(data->server);
				// still running as root? :/ don't be nice, just quit
				log_action(LOG_CRIT, "ERROR: Could not drop privileges, quitting immediately");
				fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_connect_failed);
				SAFE_CLOSE(data->client);
				exit(0);
			}
			errno = res;
			break;
#else
		// should never happen
			wait_for_quit(data, "%s", config.msg_lookup_unknown);
			break;
#endif
		case MODE_FIXED:
		case MODE_FIXED_XCLIENT:
		case MODE_GETSOCKNAME:
		case MODE_XRELAY:
		case MODE_NETFILTER:
		case MODE_IPFW:
		case MODE_IPFILTER:
		case MODE_PF:
		case MODE_REMOTE:
		case MODE_REMOTE_UDP:
			data->server = connect_host(data->target, ntohs(data->target.sin_port), src, ARRAY(int, SO_REUSEADDR, 0), NULL);
			break;
		default:
			log_action(LOG_CRIT, "!BUG! target_connect(): data->mode=%d", data->mode);
			fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_connect_failed);
			SAFE_CLOSE(data->client);
			exit(0);
	}

	if (data->server == -1) {
		res = errno;
		helo(data->client);
		if (res == EINTR || res == ETIMEDOUT) {
			wait_for_quit(data, "%s [%s]", config.msg_connect_timeout, data->target_str);
		} else {
			wait_for_quit(data, "%s [%s]: %s", config.msg_cannot_connect, data->target_str, strerror(res));
		}
		exit(5);
	}

	CLEAR_TIMEOUT();
	return 0;
} /* target_connect() */



/*
 * 	CHUNKING
*/

line_status bdat_chunk(struct session_t *data, int allow_read)
{
	int size;
	int res;

	// TODO: co jesli klient da od razu "BDAT 0 LAST"?

	// nie mozemy zrobic od razu read(), bo moglismy tu trafic z danymi
	// pozostalymi z fdgetline_cb() i kolejny read() moglby zablokowac
	size = min(config.buffer_size - data->cli_size, data->bdat_togo);
	if (allow_read && size) {
		res = read(data->client, data->cli_buf + data->cli_size, size);
		if (res == -1) {
#ifdef SILENT_ECONNRESET
			if (errno == ECONNRESET) return LINE_CLOSED;
#endif
			log_action(LOG_ERR, "bdat_chunk:read(%d): %s", size, strerror(errno));
			return LINE_CLOSED;
		}

		data->cli_size += res;
		data->cli_rx += res;
		// === if (res == 0)
		if (!data->cli_size) return LINE_CLOSED;	// a moze blad?
	}

	size = min(data->bdat_togo, data->cli_size);
	spool_write(data, data->cli_buf, size);

	for (;;) {
		if ((res = write(data->server, data->cli_buf, size)) == -1) {
			if (errno == EINTR) continue;
#ifdef SILENT_ECONNRESET
			if (errno == ECONNRESET) return LINE_CLOSED;
#endif
			log_action(LOG_ERR, "bdat_chunk:write(%d):error: %s", size, strerror(errno));
			return LINE_CLOSED;
		}

		if (res == 0) {
			log_action(LOG_ERR, "bdat_chunk:write(%d) returned 0 (connection lost)", size);
			return LINE_CLOSED;
		}

		break;
	}

	data->bdat_togo -= size;
	data->cli_size -= size;
	if (data->cli_size) memmove(data->cli_buf, data->cli_buf+size, data->cli_size);

	if (!data->bdat_togo && data->bdat_last) {
			spool_close(data);
			// TODO: scanning, BDAT 0 LAST/QUIT
	}

	return LINE_OK;
} /* bdat_chunk() */

/*
 * 	obsluga sesji
*/

int xclient_startup(struct session_t *data)
{
	char buffer[1024], *line;
	int temp1, temp2, xclient_support;
	char *xclient_name;

	temp1 = temp2 = 0;
	xclient_support = 0;
	xclient_name = "[UNAVAILABLE]";


	// resolv data->origin.sin_addr.s_addr to xclient_name
	// ...

	// read initial MTA greeting
	SET_TIMEOUT(config.timeout_lookup);
	if ((line = fdgetline(data->server, buffer, sizeof(buffer), &temp1, &temp2)) == NULL)
		goto error;
	if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%" FORMAT_PID_T "] <= %s\n", getpid(), line);
	if (strstr(line, "ESMTP") == NULL) {
		log_action(LOG_WARNING, "XCLIENT:ESMTP not supported by MTA");
		goto quit;
	}

	// EHLO
	fdprintf(data->server, "EHLO %s\r\n", config.proxy_name);
	for (;;) {
		if ((line = fdgetline(data->server, buffer, sizeof(buffer), &temp1, &temp2)) == NULL)
			goto error;
		if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%" FORMAT_PID_T "] <= %s\n", getpid(), line);
//		if (strlen(line) < 4) goto error;
		if (strstr(line, "XCLIENT") != NULL) xclient_support = 1;
		if (line[3] != '-') break;
	}
	if (strncmp(line, "250 ", 4) != 0) {
		log_action(LOG_WARNING, "XCLIENT:EHLO error=[%s]", line);
		goto quit;
	}

	// XCLIENT supported?
	if (!xclient_support) {
		log_action(LOG_WARNING, "XCLIENT:XCLIENT not supported by MTA");
		goto quit;
	}

	// XCLIENT
	fdprintf(data->server, "XCLIENT ADDR=%d.%d.%d.%d NAME=%s\r\n", NIPQUAD(data->origin.sin_addr.s_addr), xclient_name);
	if ((line = fdgetline(data->server, buffer, sizeof(buffer), &temp1, &temp2)) == NULL)
		goto error;
	if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%" FORMAT_PID_T "] <= %s\n", getpid(), line);
	if (strncmp(line, "220 ", 4) != 0) {
		log_action(LOG_WARNING, "XCLIENT:NEGATIVE error=[%s]", line);
		goto quit;
	}

	// XCLIENT successful: forward XCLIENT-ack as MTA greeting to client
	fdprintf(data->client, line);
	fdprintf(data->client, "\r\n");
	return 0;

error:
	if (errno) log_action(LOG_WARNING, "XCLIENT:ERROR %s", strerror(errno));
	// timeout: don't wait for response to QUIT...
quit:
	CLEAR_TIMEOUT();
	fdprintf(data->server, "QUIT\r\n");
	line = fdgetline(data->server, buffer, sizeof(buffer), &temp1, &temp2);
	if (IS_FLAG_SET(foreground, FORE_LOG_TRAFFIC)) fprintf(stderr, "[%" FORMAT_PID_T "] => %s\n", getpid(), line);
	SAFE_CLOSE(data->server);
	return -1;
	// read MTA greeting, check SMTP/ESMTP
	// send HELO/EHLO config.proxy_name
	// read HELO/EHLO response and extensions
	// send XCLIENT NAME=spike.porcupine.org ADDR=168.100.189.2
	// verify response code & forward to client (as MTA greeting)
	// return to session tracking, filtering "XCLIENT" extension&verbs
}

void connection(struct session_t *data)
	__attribute__ ((noreturn));

void connection(struct session_t *data)
{
	fd_set rfds;
	struct timeval tv;
	int res, max_fd;


	// pid, src filled by parent process
	SHARED_CONN_STATUS(state, CONN_IDENT);
	SHARED_CONN_STATUS(cli_rx, 0);
	SHARED_CONN_STATUS(srv_rx, 0);

	session_init_2(data);

	// dane serwera docelowego
	if (!target_lookup(data)) exit(1);

	if (lockfile_ident_present(data)) {
		SHARED_STATS_INC(rejects_lock);
		fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_virus_locked);
		SAFE_CLOSE(data->client);
		exit(0);
	}

	if (ratelimit_init(data) == -1) {
		SHARED_STATS_INC(errors_ratelimit);
		fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_ratelimit_error);
		SAFE_CLOSE(data->client);
		exit(0);
	}

	if (ratelimit_uint(data, RATELIMIT_INT_CONNECTIONS, 1)) {
		SHARED_STATS_INC(rejects_rate);
		fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_rate_reject);
		SAFE_CLOSE(data->client);
		exit(0);
	}

	// check DNS Block Lists
	// if auth_skip=dnsbl, we need to check this after authentication
	// has been possible (before MAIL FROM, RCPT TO or DATA)
	if (config.dnsbl && !IS_FLAG_SET(config.auth_skip, AUTH_SKIP_DNSBL)) {
		SHARED_CONN_STATUS(state, CONN_DNSBL);
		res = dnsbl_check(data);
		switch (res) {
			case 0: /* OK */
				break;
			case -1: /* error */
			case 1:	/* found in dnsbl */
				SHARED_STATS_INC(rejects_dnsbl);
#if 0
				log_action(LOG_DEBUG, "DNSBL:REJECT from=%d.%d.%d.%d:%d to=%d.%d.%d.%d:%d",
					NIPQUAD(data->origin), ntohs(data->origin_sin_port),
					NIPQUAD(data->target), ntohs(data->target.sin_port));
#endif
				found(data, LOCK_ON_DNSBL, FOUND_DNSBL, "DNSBL");
				fdprintf(data->client, "%03d %s %s: %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_dnsdb_reject,
					!EMPTY_STRING(data->message) ? data->message : "-");
				SAFE_CLOSE(data->client);
				exit(0);
		}
	}

	// log
	log_action(LOG_NOTICE|LOG_ALWAYS, "NEW (%d/%d) on=%s:%d, src=%s:%d, ident=%s, dst=%s:%d, id=%" FORMAT_TIME_T ".%" FORMAT_PID_T,
		children, data->ident_count, inet_ntoa(data->local.sin_addr), ntohs(data->local.sin_port), data->origin_str, ntohs(data->origin.sin_port),
		data->ident, data->target_str, ntohs(data->target.sin_port), data->start_time, getpid());

	// nie bedzie petli?
	// dla testow wylacz (albo: wlacz jesli !fixed)
	if (!foreground && (data->mode != MODE_FIXED) && (data->mode != MODE_FIXED_XCLIENT)) {
		if (data->origin.sin_addr.s_addr == data->target.sin_addr.s_addr) {
			log_action(LOG_WARNING, "Avoiding loop, exiting.");
			fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_loop_avoidance);
			SAFE_CLOSE(data->client);
			cleanup_exit(1);
		}
	}

	// sygnaly
	setup_signal();

#warning TEST:ratelimit_ip
	if (ratelimit_ip(data, RATELIMIT_IP_DST, data->target.sin_addr.s_addr)) {
		fdprintf(data->client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_ratelimit_dst);
		SAFE_CLOSE(data->client);
		cleanup_exit(1);
	}

	// podlaczenie do docelowego serwera SMTP
	if (target_connect(data) != 0) exit(1);

	if (geteuid() == 0 || getuid() == 0)
		log_action(LOG_CRIT, "!child process has root privileges!");

	// przygotowanie naglowka nat
	prepare_nat_header(data);

	// XCLIENT
	if (data->mode == MODE_FIXED_XCLIENT) {
		if (xclient_startup(data) == -1)
			wait_for_quit(data, "%s", config.msg_fixed_xclient_fail);
		// xclient_startup eats initial greeting and forwards it to client directly
		// so queueing COMMAND_GREETING would confuse pipelining support
	} else {
		// not a real command, but we'll get initial greeting from MTA
		queue_command(COMMAND_GREETING, data);
	}

	// deskryptor dla select-a
	max_fd = (data->client > data->server) ? data->client : data->server;

	SHARED_CONN_STATUS(state, CONN_PRE);

	// petla obslugi sesji
	for (;;) {
		if (force_finish) {
			res = LINE_CLOSED_ADMIN;
			break;
		}

		FD_ZERO(&rfds);
		FD_SET(data->client, &rfds);
		FD_SET(data->server, &rfds);
		tv.tv_sec = config.timeout_idle;
		tv.tv_usec = 0;

		// oczekiwanie na dane lub timedout
		if ((res = select(max_fd+1, &rfds, NULL, NULL, &tv)) == -1) {
			if (errno == EINTR) continue;
			log_action(LOG_ERR, "select: %s", strerror(errno));
			continue;
		}

		// timedout
		if (res == 0) {
			res = LINE_CLOSED_TIMEOUT;
			break;
		}

		// dane od klienta
		if (FD_ISSET(data->client, &rfds)) {
			if (data->bdat_togo) {
				if ((res = bdat_chunk(data, 1)) == LINE_CLOSED)
					break;
			}

			// nie moze byc w "else", bo po zakonczeniu bdat_chunk moga zostac jakies dane w buforze
			if (!data->bdat_togo) {
				assert(data->cli_size < config.buffer_size);
				res = fdgetline_cb(data->client, data->cli_buf, config.buffer_size,
					&data->cli_size, &client_callback, data, &data->cli_rx);
				if (res == LINE_CLOSED) break;

				// cos moglo zostac w budorze
				// if (res == LINE_BINARY?) ?
				if (data->cli_size && data->bdat_togo) {
					if ((res = bdat_chunk(data, 0)) == LINE_CLOSED) break;
				}
			}

			SHARED_CONN_STATUS(cli_rx, data->cli_rx);
		}

		// dane z serwera
		if (FD_ISSET(data->server, &rfds)) {
			assert(data->srv_size < config.buffer_size);
			res = fdgetline_cb(data->server, data->srv_buf, config.buffer_size,
				&data->srv_size, &server_callback, data, &data->srv_rx);

			SHARED_CONN_STATUS(srv_rx, data->srv_rx);

			if (res == LINE_CLOSED) {
				res = LINE_CLOSED_SERVER;
				break;
			}
		}
	}

	// porzadki

	SAFE_CLOSE(data->client);
	SAFE_CLOSE(data->server);

	if (!data->transaction) SHARED_STATS_INC(requests_empty);

	if (!IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ALWAYS))
		spool_remove(data);

	cleanup();

	log_action(LOG_NOTICE|LOG_ALWAYS, "CLOSE by=%s, rcv=%d/%d, trns=%d, rcpts=%d, auth=%d, time=%" FORMAT_TIME_T ", src=%s, ident=%s",
		line_closed_cause(res), data->cli_rx, data->srv_rx, data->transaction, data->rcpts_total, data->auth,
		time(NULL)-data->start_time, data->origin_str, data->ident);
	exit(0);
} /* connection() */

#ifdef HAVE_SETRLIMIT
void set_rlimits()
{
	// not critical, do not terminate on error
#if defined(HAVE_DECL_RLIMIT_CORE) && HAVE_DECL_RLIMIT_CORE
	if (config.limit_core_size >= 0) set_rlimit(RLIMIT_CORE, config.limit_core_size);
#endif
#if defined(HAVE_DECL_RLIMIT_AS) && HAVE_DECL_RLIMIT_AS
	if (config.limit_virt_size > 0) set_rlimit(RLIMIT_AS, config.limit_virt_size);
#endif
#if defined(HAVE_DECL_RLIMIT_DATA) && HAVE_DECL_RLIMIT_DATA
	if (config.limit_data_size > 0) set_rlimit(RLIMIT_DATA, config.limit_data_size);
#endif
#if defined(HAVE_DECL_RLIMIT_FSIZE) && HAVE_DECL_RLIMIT_FSIZE
	if (config.limit_fsize >= 0) set_rlimit(RLIMIT_FSIZE, 8192+max3(config.limit_fsize, spool_max_size, 0));
#endif
}
#endif


void auto_proxy_name()
{
#ifdef HAVE_GETHOSTNAME
	char hn[64], dn[64], buf[128];
	if (gethostname(hn, sizeof(hn)) == 0 && getdomainname(dn, sizeof(dn)) == 0) {
		TERMINATE_STRING(hn);
		TERMINATE_STRING(dn);
		if (strcmp(dn, "(none)") == 0 || strcmp(dn, "") == 0)
			snprintf(buf, sizeof(buf), "%s", hn);
		else
			snprintf(buf, sizeof(buf), "%s.%s", hn, dn);
		TERMINATE_STRING(buf);
		free(config.proxy_name);
		config.proxy_name = strdup(buf);
	} else {
		log_action(LOG_ERR, "gethostname() or getdomainname() failed: %s", strerror(errno));
		free(config.proxy_name);
		config.proxy_name = strdup("smtp-gated.isp");
	}
#else
	log_action(LOG_WARNING, "gethostname() not supported, cannot determine proxy_name");
	free(config.proxy_name);
	config.proxy_name = strdup("smtp-gated.isp");
#endif
	log_action(LOG_DEBUG, "using proxy_name=%s", config.proxy_name);
}

/*
 * 	post-reconfiguration, called:
 * 	1. after daemonize() on start
 * 	2. after reading configuration on HUP
*/

int post_config()
{
	log_level = config.log_level;

	spool_max_size = max(config.scan_max_size, config.spam_max_size);
	if (config.pipeline_size < PIPELINE_SIZE_MIN) config.pipeline_size = PIPELINE_SIZE_MIN;

	if (!EMPTY_STRING(config.locale)) {
		setlocale(LC_MESSAGES, config.locale);
//		log_action(LOG_DEBUG, "Changed locale to %s ['Success'=>'%s']", config.locale, strerror(0));
	}

#ifdef HAVE_SETRLIMIT
	set_rlimits();
#endif

	if (geteuid() == 0) {
		log_action(LOG_CRIT, "we are running as root, you freak! BANZAAAI!");
	}

	switch (config.mode) {
		case MODE_FIXED:
		case MODE_FIXED_XCLIENT:
			if (EMPTY_STRING(config.fixed_server)) {
				log_action(LOG_CRIT, "Mode set to fixed or fixed+xclient, but fixed_server empty!");
				return 1;
			}
			break;
		case MODE_TPROXY:
		case MODE_TPROXY_OR_NETFILTER:
#ifdef USE_NAT_TPROXY
			if (elevate_privileges() != 0)
				cleanup_exit(0);

			if (tproxy_check() != 0) {
				log_action(LOG_CRIT, "TPROXY version mismatch or no kernel support!");
				return 1;
			}

			if (lower_privileges() != 0)
				cleanup_exit(0);
#else
			log_action(LOG_CRIT, "TPROXY support not compiled in!");
			return 1;
#endif
		case MODE_PF:
			// TODO: /dev/pf exists and is accesible?
			break;
		case MODE_NETFILTER:
		case MODE_IPFW:
		case MODE_GETSOCKNAME:
		case MODE_REMOTE:
		case MODE_REMOTE_UDP:
			break;

		default:
		// case MODE_NONE:
			log_action(LOG_CRIT, "Invalid mode");
			return 1;
	}

	if (dnsbl_parse())
		return 1;

#ifdef USE_REGEX
	if (regex_parse())
		return 1;
#endif

	// check if directory exists, is a directory and is writable
	// check_directory(config.*)

	if (strcmp(config.proxy_name, "*") == 0)
		auto_proxy_name();

	return 0;
} /* post_config() */


/* issued only once, after post_config() on startup */
int setup_once()
{
	srandom((unsigned int) getpid() ^ time(NULL));

	// config.max_connections defined during startup only,  this setting is ignored during reload
	max_connections_real = config.max_connections;
	pid_hash_size_real = config.pid_hash_size;
	host_hash_size_real = config.host_hash_size;

	// use hashing, all other function depend on pid_hash_table being (not-)NULL
	if (max_connections_real > SLOT_HASH_THRESHOLD) {
		log_action(LOG_NOTICE, "Connection limit set high: enabling PID hashing");
		if ((pid_hash_table = calloc(pid_hash_size_real, sizeof(struct slot_hash_entry_t *))) == NULL) {
			log_action(LOG_CRIT, "pid_hash_table calloc failed: %s", strerror(errno));
			return -1;
		}

		if ((host_hash_table = calloc(host_hash_size_real, sizeof(struct host_hash_entry_t *))) == NULL) {
			log_action(LOG_CRIT, "host_hash_table calloc failed: %s", strerror(errno));
			return -1;
		}

		// create free slots queue
		int i;
		for (i=0; i<max_connections_real; i++) {
			struct slot_hash_entry_t *slot = malloc(sizeof(struct slot_hash_entry_t));
			slot->slot = i;
			slot->next = free_slots;
			free_slots = slot;
		}

	}

	pids = malloc(sizeof(pid_t) * max_connections_real);
	if (pids == NULL) return -1;

#ifdef USE_SHARED_MEM
	if ((connections = shmalloc(sizeof(struct scoreboard_t) * max_connections_real, &conn_shmid)) == NULL) {
		log_action(LOG_CRIT, "connections shmalloc failed: %s", strerror(errno));
		return -1;
	}

	if ((stats = shmalloc(sizeof(struct stat_info), &stat_shmid)) == NULL) {
		log_action(LOG_CRIT, "stats shmalloc failed: %s", strerror(errno));
		return -1;
	}
#else
	connections = malloc(sizeof(struct scoreboard_t) * max_connections_real);
	if (connections == NULL) {
		log_action(LOG_CRIT, "connections malloc failed: %s", strerror(errno));
		return -1;
	}

	if ((stats = malloc(sizeof(struct stat_info))) == NULL) {
		log_action(LOG_CRIT, "stats malloc failed: %s", strerror(errno));
		return -1;
	}
#endif

	return 0;
} /* setup */



char* chrootize_path(char *path)
{
	static char buf[256];

	snprintf(buf, sizeof(buf), "%s%s%s", config.chroot_path, EMPTY_STRING(config.chroot_path) ? "" : "/./", path);
	TERMINATE_STRING(buf);

	return buf;
} /* chrootize_path () */


void dump_help()
{
	printf("SMTP Transparent AV proxy %s\n", VERSION);
	printf("Usage: smtp-gated [-f] [ -h | -C name | -L file | -s | -S | -r | -t | -T | -v | -V ] config_file\n");
	printf("	-C name   show effective value for config variable\n");
//	printf("	-D 0xNN   debugging flags (this has nothing to do with log_level)\n");
	printf("	-f        run foreground, do not fork (for testing/debugging)\n");
	printf("	-h        this command reference\n");
	printf("	-L        dump ratelimit file contents\n");
//	printf("	-P        pid file name\n");
	printf("	-s        prepare & dump process status\n");
	printf("	-S        prepare & show process status filename\n");
	printf("	-r        reload configuration (simple SIGHUP)\n");
	printf("	-K        terminate running daemon (simple SIGTERM)\n");
	printf("	-t        syntax check & dump configuration (except messages)\n");
	printf("	-T        syntax check & dump configuration (including messages)\n");
	printf("	-v        show version\n");
	printf("	-V        show version & compiled-in options\n");
	printf("Signals:\n");
	printf("	HUP       reload configuration\n");
	printf("	USR1      dump statistics\n\n");
} /* dump_help() */


// petla glowna

#define SET_MODE(x) if (cmd == CMD_DEFAULT) cmd = x; else cmd = CMD_MANY;
typedef enum {CMD_DEFAULT=0, CMD_MANY, CMD_C, CMD_H, CMD_KK, CMD_LL,
	CMD_V, CMD_VV, CMD_T, CMD_TT, CMD_R, CMD_S, CMD_SS} run_cmd;

int main(int argc, char* argv[])
{
	run_cmd cmd = CMD_DEFAULT;
	char *arg1 = "";
	int i;
#if 0
	char *force_pidfile;
#endif

#if 0
	// [29146] !BUG! smtp-gated.c:main:2732 testing: 1
	foreground = 1;
	BUG("testing: %d", 1);
	exit(1);
#endif

	confvars_init(&config);

	for (i=1; i<argc; i++) {
		if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0)) {
			SET_MODE(CMD_H);
		} else if (strcmp(argv[i], "-v") == 0) {
			SET_MODE(CMD_V);
		} else if (strcmp(argv[i], "-V") == 0) {
			SET_MODE(CMD_VV);
		} else if (strcmp(argv[i], "-t") == 0) {
			SET_MODE(CMD_T);
		} else if (strcmp(argv[i], "-T") == 0) {
			SET_MODE(CMD_TT);
		} else if (strcmp(argv[i], "-r") == 0) {
			SET_MODE(CMD_R);
		} else if (strcmp(argv[i], "-K") == 0) {
			SET_MODE(CMD_KK);
		} else if (strcmp(argv[i], "-s") == 0) {
			SET_MODE(CMD_S);
		} else if (strcmp(argv[i], "-S") == 0) {
			SET_MODE(CMD_SS);
		} else if (strcmp(argv[i], "-f") == 0) {
			foreground |= FORE_SINGLE;
		} else if (strcmp(argv[i], "-D") == 0) {
			if (i+1 >= argc) {
				fprintf(stderr, "command line option %s requires an argument.\n", argv[i]);
				exit(1);
			}
			foreground = strtol(argv[++i], NULL, 0);
#if 0
		} else if (strcmp(argv[i], "-P") == 0) {
			if (i+1 >= argc) {
				fprintf(stderr, "command line option %s requires an argument.\n", argv[i]);
				exit(1);
			}
			force_pidfile = argv[++i];
#endif
		} else if (strcmp(argv[i], "-C") == 0) {
			SET_MODE(CMD_C);
			if (i+1 >= argc) {
				fprintf(stderr, "command line option %s requires an argument.\n", argv[i]);
				exit(1);
			}
			arg1 = argv[++i];
		} else if (strcmp(argv[i], "-L") == 0) {
			SET_MODE(CMD_LL);
			if (i+1 >= argc) {
				fprintf(stderr, "command line option %s requires an argument.\n", argv[i]);
				exit(1);
			}
			arg1 = argv[++i];
		} else {
			if (*argv[i] == '-') {
				fprintf(stderr, "Fatal: Unknown option: %s\n", argv[i]);
				exit(1);
			} else {
				if (config_file) {
					fprintf(stderr, "Fatal: You can supply only one configuration file!\n");
					exit(1);
				}

				config_file = argv[i];
			}
		}
	}

	if (cmd == CMD_MANY) {
		fprintf(stderr, "Fatal: You can specify only one mode\n");
		exit(3);
	}

#ifdef DEFAULT_CONFIG_FILE
	if (!config_file) config_file = DEFAULT_CONFIG_FILE;
#endif

	foreground++;
	if (config_file) {
		if (read_config(config_options, config_file) != 0) {
			if (config_file[0] == '-') fprintf(stderr, "Try %s -h for help\n", argv[0]);
			exit(2);
		}
	}
	foreground--;

	if (foreground) fprintf(stderr, "Foreground level: 0x%02x\n", foreground);

	switch (cmd) {
		case CMD_DEFAULT:
			break;
		case CMD_H:
			dump_help();
			exit(10);
		case CMD_C:
			// nie bierze pod uwag� chroot-a w przypadku �cie�ek!
			i = dump_config_by_name(arg1, config_options, 0);
			exit(i);
		case CMD_KK:
			if (pidfile_signal(SIGTERM, chrootize_path(config.pidfile)) != 0) exit(1);
			exit(0);
		case CMD_LL:
			foreground = 1;
			i = ratelimit_dump(arg1);
			exit(i < 0 ? 1 : i);
		case CMD_R:
			if (pidfile_signal(SIGHUP, chrootize_path(config.pidfile)) != 0) exit(1);
			exit(0);
		case CMD_V:
		case CMD_VV:
			dump_ver(cmd == CMD_VV);
			exit(0);
		case CMD_T:
		case CMD_TT:
			dump_config(config_options, (cmd == CMD_TT));
			exit(0);
		case CMD_S:
		case CMD_SS:
			if (pidfile_signal(SIGUSR1, chrootize_path(config.pidfile)) != 0) exit(1);
			sleep(1);
			if (cmd == CMD_SS) {
				printf("%s\n", chrootize_path(config.statefile));
			} else {
				i = cat(chrootize_path(config.statefile));
				if (i) exit(1);
			}
			exit(0);
		default:
			fprintf(stderr, "Fatal: !BUG! unknown exec cmd [%d]\n", cmd);
			exit(3);
	}

	if (!config_file) {
		fprintf(stderr, "Fatal: Config file not supplied.\n");
		exit(1);
	}

	// also updated later by post_config
	log_level = config.log_level;

	if (daemonize("smtp-gated", config.log_facility, config.priority, config.chroot_path,
		IS_FLAG_SET(foreground, FORE_SINGLE) ? "" : config.pidfile, config.set_user, config.set_group,
		(config.mode == MODE_TPROXY || config.mode == MODE_TPROXY_OR_NETFILTER) ? DAEMONIZE_SET_EUID_ONLY : 0) != 0) exit(1);

	if (chdir(config.spool_path) != 0) {
		log_action(LOG_CRIT, "chdir(%s): %s", config.spool_path, strerror(errno));
		cleanup_exit(1);
	}

	if (post_config() != 0)
		cleanup_exit(1);

	if (setup_once() != 0)
		cleanup_exit(1);

	/* start */
	int res, count, slot;
	int client, proxy;
	struct timeval tv;
	struct sockaddr_in origin;
	socklen_t originlen;
	double cur_load;
	struct session_t data;
	struct host_hash_entry_t *hostslot;


	memset(connections, 0, sizeof(struct scoreboard_t) * max_connections_real);
	memset(pids, 0, sizeof(pid_t) * max_connections_real);
	memset(stats, 0, sizeof(struct stat_info));
	memset(&data, 0, sizeof(struct session_t));

	stats->started = time(NULL);
	proxy = -1;

restart:
	stats->restarted = time(NULL);

	if ((res = setup_signal()) < 0) {
		log_action(LOG_CRIT, "setup_signal: %s", strerror(errno));
		cleanup();
		exit(1);
	}

	if (proxy == -1) {
		switch (config.mode) {
#ifdef USE_NAT_TPROXY
			case MODE_TPROXY:
			case MODE_TPROXY_OR_NETFILTER:
				if (elevate_privileges() != 0)
					cleanup_exit(0);

				proxy = setup_socket(IPPROTO_TCP, config.bind_address, config.port,
					config.connect_queue, ARRAY(int, SO_REUSEADDR, 0), ARRAY(int, IP_TRANSPARENT, 0));

				if (lower_privileges() != 0)
					cleanup_exit(0);
				break;
#endif
			default:
				proxy = setup_socket(IPPROTO_TCP, config.bind_address, config.port,
					config.connect_queue, ARRAY(int, SO_REUSEADDR, 0), NULL);
		}
		if (proxy == -1)
			cleanup_exit(1);

		log_action(LOG_INFO, "SMTP-Proxy %s listening on %s:%d/TCP [queue: %d]", VERSION, config.bind_address, config.port, config.connect_queue);
	}

	/* to improve test-suite performance */
	debug_stage("READY");

	/* main server loop */
	for (;;) {
		if (force_finish) {
			force_finish = 0;
			break;
		}
		if (child_died) {
			// nie ma wyscigow, bo child_reaper obsluzy wszystkie zakonczone procesy
			child_died = 0;
			child_reaper();
		}
		if (force_reconfig) {
			force_reconfig = 0;
			log_action(LOG_INFO, "Reloading configuration...");
			if (read_config(config_options, config_file) != 0) {
				log_action(LOG_CRIT, "Error parsing configuration file...");
				// inconsistent configuration
				break;
			}
			if (post_config() != 0) {
				log_action(LOG_CRIT, "Invalid configuration...");
				// inconsistent configuration
				break;
			}
			if ((config.port >= 1024) || (getuid() == 0)) {
				SAFE_CLOSE(proxy);
			} else {
				log_action(LOG_NOTICE, "NOTICE: listening socket won't be reopened...");
			}

			goto restart;
		}

		if (force_dump) {
			force_dump = 0;
			dump_state();
		}

		originlen = sizeof(origin);
		if ((client = accept(proxy, (struct sockaddr*) &origin, &originlen)) == -1) {
			// signal
			if (errno == EINTR || errno == EAGAIN) continue;
			// may occur on FreeBSD if connection was aborted before accept()
			// zawracanie d4 zbednymi rzeczami
			if (errno == ECONNABORTED || errno == ECONNRESET) continue;
			if (errno == ENFILE) {
				log_action(LOG_CRIT, "accept: %s; sleeping for %d seconds", strerror(errno), config.enfile_sleep);
				sleep(config.enfile_sleep);
				continue;
			}
			log_action(LOG_CRIT, "accept error: %s", strerror(errno));
			break;
		}

		log_action(LOG_DEBUG, "ACCEPT: from=%d.%d.%d.%d:%d", NIPQUAD(origin.sin_addr), ntohs(origin.sin_port));
		stats->requests++;

		/* memleak testing */
#ifdef MEMLEAK_TESTING
		#warning MEMLEAK TESTING
		log_action(LOG_WARNING, "MEMLEAK_TESTING defined, allocating bogus %s bytes", MEMLEAK_TESTING);
		malloc(MEMLEAK_TESTING);
#endif

		/* fast DoS checks */
		if (children >= max_connections_real) {
			log_action(LOG_INFO, "Rejecting (%d) connection from %s:%d", children, inet_ntoa(origin.sin_addr), ntohs(origin.sin_port));
			fdprintf(client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_max_reached);
			SAFE_CLOSE(client);
			stats->rejects_other++;
			continue;
		}

		if (is_load_above(config.max_load, &cur_load) == 1) {
			log_action(LOG_INFO, "Rejecting connection from %s:%d, load=%f", inet_ntoa(origin.sin_addr), ntohs(origin.sin_port), cur_load);
			fdprintf(client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_system_load);
			SAFE_CLOSE(client);
			stats->rejects_other++;
			continue;
		}

		if (pid_hash_table) {
			slot = slot_peek();
			count = host_count(origin.sin_addr.s_addr, &hostslot);
		} else {
			/* find free slot and count connections from origin at the same time */
			for (slot = SLOT_NOT_FOUND, count=0, i=0; i<max_connections_real; i++) {
				if (pids[i] == 0) {
					slot = i;
				} else {
					if (connections[i].src == SIN_TO_UINT32(origin.sin_addr)) count++;
				}
			}
		}

		// free previous context
		session_free(&data);
		session_init_1(&data, client, origin);

		// count is equal to number of connection coming from the same IP, except the current one
		if (count >= config.max_per_host) {
			log_action(LOG_INFO, "Rejecting (host %d) connection from %s:%d", count, inet_ntoa(origin.sin_addr), ntohs(origin.sin_port));
			fdprintf(client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_max_per_host);
			found(&data, LOCK_ON_MAX_HOST, FOUND_MAX_HOST, "MAX_HOST");
			SAFE_CLOSE(client);
			stats->rejects_host++;
			continue;
		}

		if (slot == SLOT_NOT_FOUND) {
			// if all slots are busy, we should not even get so far
			log_action(LOG_ALERT, "!BUG! No free slot, but max_connections_real=%d, rejecting connection from %s:%d", max_connections_real, inet_ntoa(origin.sin_addr), ntohs(origin.sin_port));
			fdprintf(client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_temp_unavail);
			SAFE_CLOSE(client);
			stats->rejects_other++;
			continue;
		}

		if (config.lock_duration && lockfile_present(&data)) {
			fdprintf(client, "%03d %s %s\n", CONN_REJ_CODE, config.proxy_name, config.msg_virus_locked);
			SAFE_CLOSE(client);
			stats->rejects_lock++;
			continue;
		}

		memset(&connections[slot], 0, sizeof(struct scoreboard_t));
		connections[slot].src = SIN_TO_UINT32(origin.sin_addr);
		connections[slot].start_time = time(NULL);
#ifdef USE_SHARED_MEM
		connections[slot].ident_ok =
			connections[slot].dst =
			connections[slot].cli_rx =
			connections[slot].srv_rx =
			connections[slot].transaction = 0;
		connections[slot].state = CONN_START;
#endif

		/* fork & service request */
		pid_t pid = IS_FLAG_SET(foreground, FORE_SINGLE) ? 0 : fork();
		if (pid < 0) {
			log_action(LOG_CRIT, "fork error: %s", strerror(errno));
			break;
		}

		// increase for both parent and child
		if (++children > stats->max_children)
			 stats->max_children = children;

		if (!pid) {
			i_am_a_child = 1;

#ifdef USE_SHARED_MEM
			child_slot = slot;
#endif

			/* free and forget for security reasons */
			/* maybe memset('\0')? */
			free(pids);
			pids = NULL;

			SAFE_CLOSE(proxy);
			connection(&data);
			cleanup_exit(0);
		}

		// parent
		pids[slot] = pid;
		slot_use(slot, pid);
		host_inc(connections[slot].src, hostslot);
		SAFE_CLOSE(client);
	}

	SAFE_CLOSE(proxy);


	if (children) {
		pidfile_remove(config.pidfile);
		// hack => cleanup() nie bedzie probowal usunac ponownie
		if (config.pidfile) config.pidfile[0] = '\0';
		log_action(LOG_INFO, "Listening-socket closed, waiting for %d children(s) to finish", children);
	}

	while (children) {
		if (force_dump) {
			force_dump = 0;
			dump_state();
		}

		if (force_finish) break;

		if (child_died) {
			child_died = 0;
			child_reaper();
			if (!children) break;
		}

		tv.tv_sec = 3;
		tv.tv_usec = 0;
		if (select(0, NULL, NULL, NULL, &tv) == -1 && errno != EINTR) {
			log_action(LOG_ERR, "select: %s", strerror(errno));
			break;
		}
	}

	debug_stage("QUIT");
	log_stats();
	log_action(LOG_INFO, "Children finished, exiting");
	cleanup();
	exit(0);
} /* main() */
