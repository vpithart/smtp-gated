/*
 *	dump.c
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
 *	headers
*/

#define _GNU_SOURCE

#define _DUMP_C_

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "confvars.h"
#include "smtp-gated.h"
#include "scan.h"
#include "dump.h"
#include "util.h"
#include "proxy-helper.h"
#include "ratelimit.h"

#ifdef USE_REGEX
#include "regex.h"
#endif

#ifdef USE_SPF
#include "spf.h"
#endif


struct option_enum statefile_type_list[] = {
	{ "slots", DUMPFILE_TYPE_SLOTS },
	{ "flat", DUMPFILE_TYPE_FLAT },
	{ "human", DUMPFILE_TYPE_HUMAN },
	{ NULL }
};


void log_stats()
{
	int d, h, m, s;

	time2dhms(time(NULL) - stats->started, &d, &h, &m, &s);	// elapsed

#ifndef USE_SHARED_MEM
	stats->rejects_ident = stats->viruses = stats->spams = stats->rejects_dnsbl =
	   stats->spf = stats->noauths = stats->requests_empty = stats->rejects_rate = -1;
#endif

	log_action(LOG_INFO, "uptime=%ud%uh%um%us maxchildren=%u" \
			" crash=%u@%" FORMAT_TIME_T " bugs=%u@%" FORMAT_TIME_T \
			" found=%u/%u/%u/%u requests=%u/%u/%u rejects=%u/%u/%u/%u/%u/%u/%u/%u",
		d, h, m, s, stats->max_children,
		stats->child_crashes, stats->child_crash_last, stats->child_bugs, stats->child_bug_last,
		stats->viruses, stats->spams, stats->noauths, stats->spf,
		stats->requests, stats->requests_direct, stats->requests_empty,
		stats->rejects_host, stats->rejects_ident, stats->rejects_lock, stats->rejects_dnsbl,
		stats->regex, stats->rejects_rate, stats->rejects_ratelimit, stats->rejects_other);
}

void dump_state()
{
	char tmp_statefile[FILENAME_MAX+1];
	struct scoreboard_t *ci;
	int fd;

	time_t now, td;
	int i, d, h, m, s;
#ifdef USE_SHARED_MEM
	double speed;
	char flags[16];
#endif
#ifdef HAVE_GETRUSAGE
	struct rusage ru;
#endif

	snprintf(tmp_statefile, sizeof(tmp_statefile), "%s.tmp", config.statefile);
	TERMINATE_STRING(tmp_statefile);

	fd = open(tmp_statefile, O_WRONLY | O_CREAT | O_TRUNC, config.statefile_perm);
	if (fd == -1) {
		log_action(LOG_ERR, "can't open dump file [%s]: %s", config.statefile, strerror(errno));
		return;
	}

	now = time(NULL);
	time2dhms(now - stats->started, &d, &h, &m, &s);	// elapsed
#ifdef USE_SHARED_MEM
	memset(flags, 0, sizeof(flags));
#else
	stats->rejects_ident = stats->viruses = stats->spams = stats->rejects_dnsbl =
		stats->regex = stats->spf = stats->noauths = stats->requests_empty =
		stats->auth_accepts = stats->auth_rejects = 0;
#endif

	if (IS_FLAG_CLEARED(config.statefile_type, DUMPFILE_TYPE_FLAT)) {
		fdprintf(fd, "Version:      %s\n", VERSION);
		fdprintf(fd, "Compile date: %s\n", compile_date());
		fdprintf(fd, "Dump time:    %s\n", time2str(now));
		fdprintf(fd, "Start time:   %s\n", time2str(stats->started));
		fdprintf(fd, "Restart time: %s\n", time2str(stats->restarted));
		fdprintf(fd, "Last crash:   %s\n", time2str(stats->child_crash_last));
		fdprintf(fd, "Last BUG:     %s\n", time2str(stats->child_bug_last));
		fdprintf(fd, "Uptime:   %ud %uh %um %us\n", d, h, m, s);
	} else {
		fdprintf(fd, "version: %s\n", VERSION);
		fdprintf(fd, "time.dump.unix: %" FORMAT_TIME_T "\n", now);
		fdprintf(fd, "time.dump.string: %s\n", time2str(now));
		fdprintf(fd, "time.start.unix: %" FORMAT_TIME_T "\n", stats->started);
		fdprintf(fd, "time.start.string: %s\n", time2str(stats->started));
		fdprintf(fd, "time.restart.unix: %" FORMAT_TIME_T "\n", stats->restarted);
		fdprintf(fd, "time.restart.string: %s\n", time2str(stats->restarted));
		fdprintf(fd, "uptime.ticks: %" FORMAT_TIME_T "\n", now - stats->started);
		fdprintf(fd, "uptime.string: %ud %uh %um %us\n", d, h, m, s);
	}
#ifdef HAVE_GETRUSAGE
	if (getrusage(RUSAGE_SELF, &ru) == 0) {
		if (IS_FLAG_CLEARED(config.statefile_type, DUMPFILE_TYPE_FLAT)) {
			fdprintf(fd, "Resource: %ld/%ld/%ld/%ld (maxrss/ixrss/idrss/isrss)\n",
				ru.ru_maxrss, ru.ru_ixrss, ru.ru_idrss, ru.ru_isrss);
		} else {
			fdprintf(fd, "Resource: %ld/%ld/%ld/%ld (maxrss/ixrss/idrss/isrss)\n",
				ru.ru_maxrss, ru.ru_ixrss, ru.ru_idrss, ru.ru_isrss);
		}
	} else {
		fdprintf(fd, "# Resource: getrusage() error: %s\n", strerror(errno));
	}
#endif
	if (IS_FLAG_CLEARED(config.statefile_type, DUMPFILE_TYPE_FLAT)) {
		fdprintf(fd, "Children: %u/%u/%u/%u (current/max/crashed/bugs)\n", children,
			stats->max_children, stats->child_crashes, stats->child_bugs);
		fdprintf(fd, "Found:    %u/%u/%u/%u/%u (viruses/spam/no-auth/spf/regex/earlytalk)\n",
			stats->viruses, stats->spams, stats->noauths, stats->spf, stats->regex, stats->earlytalk);
		fdprintf(fd, "Requests: %u/%u/%u (total/direct/empty)\n",
			stats->requests, stats->requests_direct, stats->requests_empty);
		fdprintf(fd, "Rejects:  %u/%u/%u/%u/%u/%u/%u (host/ident/lock/dnsbl/rate/ratelimit/other)\n",
			stats->rejects_host, stats->rejects_ident, stats->rejects_lock,
		   	stats->rejects_dnsbl, stats->rejects_rate, stats->rejects_ratelimit,
			stats->rejects_other);
		fdprintf(fd, "Errors:   %u (pipeline)\n",
			stats->errors_pipeline_full);
		fdprintf(fd, "Auth:     %u/%u (accepted/rejected)\n",
			stats->auth_accepts, stats->auth_rejects);
	} else {
		fdprintf(fd, "children.current: %u\n", children);
		fdprintf(fd, "children.max: %u\n", stats->max_children);
		fdprintf(fd, "children.crashes: %u\n", stats->child_crashes);
		fdprintf(fd, "children.crash_last: %" FORMAT_TIME_T "\n", stats->child_crash_last);
		fdprintf(fd, "children.bugs: %u\n", stats->child_bugs);
		fdprintf(fd, "children.bug_last: %" FORMAT_TIME_T "\n", stats->child_bug_last);
		fdprintf(fd, "found.viruses: %u\n", stats->viruses);
		fdprintf(fd, "found.spams: %u\n", stats->spams);
		fdprintf(fd, "found.noauths: %u\n", stats->noauths);
#ifdef USE_SPF
		fdprintf(fd, "found.spf: %u\n", stats->spf);
#endif
		fdprintf(fd, "found.regex: %u\n", stats->regex);
		fdprintf(fd, "found.earlytalk: %u\n", stats->earlytalk);
		fdprintf(fd, "requests.total: %u\n", stats->requests);
		fdprintf(fd, "requests.direct: %u\n", stats->requests_direct);
		fdprintf(fd, "requests.empty: %u\n", stats->requests_empty);
		fdprintf(fd, "rejects.host: %u\n", stats->rejects_host);
		fdprintf(fd, "rejects.ident: %u\n", stats->rejects_ident);
		fdprintf(fd, "rejects.lock: %u\n", stats->rejects_lock);
		fdprintf(fd, "rejects.dnsbl: %u\n", stats->rejects_dnsbl);
		fdprintf(fd, "rejects.rate: %u\n", stats->rejects_rate);
		fdprintf(fd, "rejects.ratelimit: %u\n", stats->rejects_ratelimit);
		fdprintf(fd, "rejects.other: %u\n", stats->rejects_other);
		fdprintf(fd, "errors.pipeline: %u\n", stats->errors_pipeline_full);
		fdprintf(fd, "auth.accepts: %u\n", stats->auth_accepts);
		fdprintf(fd, "auth.rejects: %u\n", stats->auth_rejects);
	}

	if (IS_FLAG_CLEARED(config.statefile_type, DUMPFILE_TYPE_FLAT)) {
		fdprintf(fd, "\n");
		fdprintf(fd, "%6s %-5s %-8s %-5s %-5s %-15s %-15s %4s %8s %8s %7s %s\n",
			"slot", "pid", "state", "flags", "time", "source", "target", "trns", "cli_rx", "srv_rx", "kbps", "ident");
	}

	if (IS_FLAG_SET(config.statefile_type, DUMPFILE_TYPE_SLOTS)) {
		for (i=0; i<max_connections_real; i++) {
			ci = &connections[i];
			if (!pids[i]) continue;

			td = now - ci->start_time;

#ifdef USE_SHARED_MEM
			if (td) {
				speed = ((float) ci->cli_rx)/(td*1024/8);
			} else {
				speed = 0;
			}
			flags[0] = IS_FLAG_SET(ci->auth, AUTH_FLAG_ACCEPTED) ? 'A' : (IS_FLAG_SET(ci->auth, AUTH_FLAG_SUPPORTED) ? 'a' : '.');

			if (IS_FLAG_CLEARED(config.statefile_type, DUMPFILE_TYPE_FLAT)) {
				fdprintf(fd, "%6u %-5" FORMAT_PID_T " ", i, pids[i]);
				fdprintf(fd, "%-8s", conn_states[ci->state]);
				fdprintf(fd, " %-5s", flags);
				fdprintf(fd, " %02" FORMAT_TIME_T ":%02" FORMAT_TIME_T, td / 60, td % 60);
				fdprintf(fd, " %-15s ", inet_ntoa(UINT32_TO_SIN(ci->src)));
				fdprintf(fd, "%-15s %4u %8u %8u %7.1f", inet_ntoa(UINT32_TO_SIN(ci->dst)), ci->transaction, ci->cli_rx, ci->srv_rx, speed);
				fdprintf(fd, " %s\n", (ci->ident_ok) ? ci->ident : "");
			} else {
				fdprintf(fd, "slot.%u.pid: %u\n", i, pids[i]);
				fdprintf(fd, "slot.%u.start.unix: %" FORMAT_TIME_T "\n", i, ci->start_time);
				fdprintf(fd, "slot.%u.start.string: %s\n", i, time2str(ci->start_time));
				fdprintf(fd, "slot.%u.state: %s\n", i, conn_states[ci->state]);
				fdprintf(fd, "slot.%u.src.ip: %s\n", i, inet_ntoa(UINT32_TO_SIN(ci->src)));
				fdprintf(fd, "slot.%u.flags: %s\n", i, flags);
			}
#else
			if (IS_FLAG_CLEARED(config.statefile_type, DUMPFILE_TYPE_FLAT)) {
				fdprintf(fd, "%4u %-5" FORMAT_PID_T " ", i, pids[i]);
				fdprintf(fd, "%-8s", "-");
				fdprintf(fd, " %02" FORMAT_TIME_T ":%02" FORMAT_TIME_T, td / 60, td % 60);
				fdprintf(fd, " %-15s ", inet_ntoa(UINT32_TO_SIN(ci->src)));
				fdprintf(fd, "%-15s %4s %8s %8s %6s\n", "-", "-", "-", "-", "-");
			} else {
				fdprintf(fd, "slot.%u.pid: %u\n", i, pids[i]);
				fdprintf(fd, "slot.%u.start.unix: %" FORMAT_TIME_T "\n", i, ci->start_time);
				fdprintf(fd, "slot.%u.start.string: %s\n", i, time2str(ci->start_time));
			}
#endif
		}
	}

	close(fd);

	// move fresh state file to its nominal name
	if (rename(tmp_statefile, config.statefile) != 0) {
		log_action(LOG_ERR, "can't rename temporary state file [%s] to [%s]: %s", tmp_statefile, config.statefile, strerror(errno));
		return;
	}
} /* dump_state() */


void dump_ver(int verbose)
{
	printf("SMTP Transparent AV proxy\n");
	CONF_SS2("version", VERSION);
	CONF_HH2("helper protocol version", PH_PROTO_VERSION);
	CONF_SS2("compile date", compile_date());

	if (!verbose) {
		printf("\nThis program is distributed under GNU GPL license, without\n");
	       	printf("any warranty. For more information see COPYING file.\n");
		return;
	}

	printf("Defines:\n");
#ifdef DEFAULT_CONFIG_FILE
	CONF_S2(DEFAULT_CONFIG_FILE);
#endif
#ifdef USE_NAT
	printf("  %-30s: %s (%s)\n", "USE_NAT", "yes", USE_NAT);
#else
	CONF_SS2("USE_NAT", "no");
#endif
#ifdef USE_SHARED_MEM
	CONF_SS2("USE_SHARED_MEM", "yes");
#else
	CONF_SS2("USE_SHARED_MEM", "no");
#endif
#ifdef USE_SPF
	CONF_SS2("USE_SPF", spf_version());
#else
	CONF_SS2("USE_SPF", "no");
#endif
#ifdef USE_REGEX
	CONF_SS2("USE_REGEX", regex_version());
#else
	CONF_SS2("USE_REGEX", "no");
#endif

#ifdef SCANNER_MKSD
	CONF_SS2("SCANNER_MKSD", "yes");
#else
	CONF_SS2("SCANNER_MKSD", "no");
#endif
#ifdef SCANNER_LIBDSPAM
	CONF_SS2("SCANNER_LIBDSPAM", "yes");
#else
	CONF_SS2("SCANNER_LIBDSPAM", "no");
#endif
/*
#ifdef USE_PGSQL
	CONF_SS2("USE_PGSQL", "yes");
#else
	CONF_SS2("USE_PGSQL", "no");
#endif
*/
#ifdef FILTER_CHUNKING
	CONF_SS2("FILTER_CHUNKING", "yes");
#else
	CONF_SS2("FILTER_CHUNKING", "no");
#endif
#ifdef SILENT_ECONNRESET
	CONF_SS2("SILENT_ECONNRESET", "yes");
#else
	CONF_SS2("SILENT_ECONNRESET", "no");
#endif
	CONF_D2(CONN_REJ_CODE);
	CONF_D2(HELO_LENGTH);
	CONF_D2(IDENT_SIZE);
	CONF_D2(PIPELINE_SIZE_MIN);
	CONF_D2(SLOT_HASH_THRESHOLD);
#ifndef HAVE_SETENV
	CONF_SS2("HAVE_SETENV", "no");
#endif
#ifdef HAVE_MMAP
	CONF_SS2("HAVE_MMAP", "yes");
#else
	CONF_SS2("HAVE_MMAP", "no");
#endif
#ifdef MEMLEAK_TESTING
	CONF_SS2("MEMLEAK_BUILDIN", "YES -- FOR TESTING ONLY!");
#endif
	printf("Extra:\n");
	CONF_D2(sizeof(struct session_t));
	CONF_D2(sizeof(struct scoreboard_t));
	CONF_D2(sizeof(struct pipeline_t));
	CONF_D2(sizeof(struct ratelimit_record_t));
} /* dump_ver() */
