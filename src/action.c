/*
 *	action.c
 *
 *	Copyright (C) 2004-2005 Bart³omiej Korupczynski <bartek@klolik.org>
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

#define _GNU_SOURCE

/* public headers */
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* private headers */

#define _ACTION_C_
#include "conffile.h"
#include "smtp-gated.h"
#include "confvars.h"
#include "util.h"
#include "action.h"
#include "daemon.h"
#include "compat.h"


/*
 * 	zrob cos innego (TM) jesli znajdziemy wirusa :)
*/

/*
 * environment:
 *
 * FOUND: { SPAM | VIRUS | UNKNOWN }
 * VIRUS_NAME, SPAM_SCORE
 * SOURCE_IP, SOURCE_PORT
 * IDENT, IDENT_COUNT
 * TARGET_IP, TARGET_PORT
 * LOCAL_IP, LOCAL_PORT
 * HELO
 * MAIL_FROM, RCPTS_TOTAL
 * SIZE, TRANSACTION
 * SPOOL_NAME
 * LOCK_FILE
 * TIME
 *
*/

void user_action(struct session_t *data)
{
	int res, n;
	char origin_port[12], target_port[12], local_port[12];
	char ident_count[12], rcpts_total[12], transaction[12], size[12];
	char auth[12];
	char spam_score[20], unixtime[12], *time, *local_ip;
	char lock_duration[20];
	char *arg[8], *found;
	
	if (EMPTY_STRING(config.action_script)) return;

	if ((res = fork()) == -1) {
		log_action(LOG_CRIT, "user_action:fork failed: %s", strerror(errno));
		return;
	}

	// parent process
	if (res != 0) return;

	// child process
	if (data->server != -1) SAFE_CLOSE(data->server);
	SAFE_CLOSE(data->client);

	(void) setsid();
	(void) drop_privileges();

	if (snprintf(spam_score, sizeof(spam_score), "%.3f", data->spam_score) == -1) goto asprintf_err;
	TERMINATE_STRING(spam_score);
	if (snprintf(origin_port, sizeof(origin_port), "%d", ntohs(data->origin.sin_port)) == -1) goto asprintf_err;
	TERMINATE_STRING(origin_port);
	if (snprintf(target_port, sizeof(target_port), "%d", ntohs(data->target.sin_port)) == -1) goto asprintf_err;
	TERMINATE_STRING(target_port);
	if (snprintf(local_port, sizeof(local_port), "%d", config.port) == -1) goto asprintf_err;
	TERMINATE_STRING(local_port);
	if (snprintf(ident_count, sizeof(ident_count), "%d", data->ident_count) == -1) goto asprintf_err;
	TERMINATE_STRING(ident_count);
	if (snprintf(rcpts_total, sizeof(rcpts_total), "%d", data->rcpts_total) == -1) goto asprintf_err;
	TERMINATE_STRING(rcpts_total);
	if (snprintf(size, sizeof(size), "%d", data->size) == -1) goto asprintf_err;
	TERMINATE_STRING(size);
	if (snprintf(transaction, sizeof(transaction), "%d", data->transaction) == -1) goto asprintf_err;
	TERMINATE_STRING(transaction);
	if (snprintf(auth, sizeof(auth), "%d", data->auth) == -1) goto asprintf_err;
	TERMINATE_STRING(auth);
	if (snprintf(unixtime, sizeof(unixtime), "%" FORMAT_TIME_T, data->start_time) == -1) goto asprintf_err;
	TERMINATE_STRING(unixtime);
	if (snprintf(lock_duration, sizeof(lock_duration), "%d", config.lock_duration) == -1) goto asprintf_err;
	TERMINATE_STRING(lock_duration);

	time = time2str(data->start_time);
	local_ip = inet_ntoa(data->local.sin_addr);
	switch (data->found) {
		case FOUND_VIRUS:
			found = "VIRUS";
			break;
		case FOUND_SPAM:
			found = "SPAM";
			break;
		case FOUND_MAX_HOST:
			found = "MAX_HOST";
			break;
		case FOUND_MAX_IDENT:
			found = "MAX_IDENT";
			break;
		case FOUND_DNSBL:
			found = "DNSBL";
			break;
		case FOUND_SPF:
			found = "SPF";
			break;
		case FOUND_REGEX_HELO_EHLO:
			found = "REGEX_HELO";
			break;
		case FOUND_REGEX_MAIL_FROM:
			found = "REGEX_MAIL_FROM";
			break;
		case FOUND_REGEX_RCPT_TO:
			found = "REGEX_RCPT_TO";
			break;
		case FOUND_EARLYTALK:
			found = "EARLYTALK";
			break;
		case FOUND_RATELIMIT_MAILFROM_REJECTS:
			found = "RATELIMIT_MAILFROM_REJECTS";
			break;
		case FOUND_RATELIMIT_RCPTTO_REJECTS:
			found = "RATELIMIT_RCPTTO_REJECTS";
			break;
		default:
			BUG("unknown lock cause: %d", data->found);
			found = "UNKNOWN";
	}

#ifdef HAVE_SETENV
	res = setenv("PROXY_NAME", config.proxy_name, 1);
	if (!res) res = setenv("FOUND", found, 1);
	if (!res) res = setenv("VIRUS_NAME", (!EMPTY_STRING(data->virus_name)) ? data->virus_name : "", 1);
	if (!res) res = setenv("SPAM_SCORE", spam_score, 1);
	if (!res) res = setenv("SOURCE_IP", data->origin_str, 1);
	if (!res) res = setenv("SOURCE_PORT", origin_port, 1);
	if (!res) res = setenv("TARGET_IP", data->target_str, 1);
	if (!res) res = setenv("TARGET_PORT", target_port, 1);
	if (!res) res = setenv("LOCAL_IP", local_ip, 1);
	if (!res) res = setenv("LOCAL_PORT", local_port, 1);
	if (!res) res = setenv("IDENT", (!EMPTY_STRING(data->ident)) ? data->ident : "", 1);
	if (!res) res = setenv("IDENT_COUNT", ident_count, 1);
	if (!res) res = setenv("HELO", (!EMPTY_STRING(data->helo)) ? data->helo : "", 1);
	if (!res) res = setenv("MAIL_FROM", (!EMPTY_STRING(data->mail_from)) ? data->mail_from : "", 1);
	if (!res) res = setenv("RCPTS_TOTAL", rcpts_total, 1);
	if (!res) res = setenv("SIZE", size, 1);
	if (!res) res = setenv("TRANSACTION", transaction, 1);
	if (!res) res = setenv("AUTH", auth, 1);
	if (!res) res = setenv("SPOOL_NAME", (data->spool_exists) ? data->spool_name : "", 1);
	if (!res) res = setenv("LOCK_FILE", (!EMPTY_STRING(data->lockfile)) ? data->lockfile : "", 1);
	if (!res) res = setenv("LOCK_DURATION", lock_duration, 1);
	if (!res) res = setenv("TIME", time, 1);
	if (!res) res = setenv("UNIXTIME", unixtime, 1);

	if (res) {
		log_action(LOG_CRIT, "user_action: insufficient space for environment");
		exit(5);
	}
#endif

	n = 0;	// !! n < argv[]
	arg[n++] = config.action_script;
	arg[n++] = found;
	arg[n++] = data->origin_str;
	arg[n++] = EMPTY_STRING(data->ident) ? "-" : data->ident;
	arg[n++] = data->target_str;
	arg[n++] = NULL;


	// no need to free allocated memory, as we are doing execv()
	if (foreground) log_action(LOG_DEBUG, "execv[%s]", config.action_script);
	res = execv(arg[0], arg);
	log_action(LOG_CRIT, "user_action:execv[%s] failed: %s", config.action_script, strerror(errno));
	exit(5);

asprintf_err:
	log_action(LOG_CRIT, "user_action:asprintf failed");
	exit(5);
} /* user_action() */




