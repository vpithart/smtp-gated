/*
 * 	spool.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#define _SPOOL_C_

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "conffile.h"
#include "smtp-gated.h"
#include "confvars.h"
#include "scan.h"
#include "lockfile.h"
#include "spool.h"
#include "util.h"


int spool_max_size = 0;


struct option_enum spool_leave_on_list[] = {
	{ "error", LEAVE_ON_ERROR },
	{ "spam", LEAVE_ON_SPAM },
	{ "virus", LEAVE_ON_VIRUS },
	{ "never", LEAVE_ON_NEVER },
	{ "always", LEAVE_ON_ALWAYS },
	{ NULL, -1 }
};

/*
 * 	funkcje obslugi spoola
*/

void spool_close(struct session_t *data)
{
	if (data->spool_fd == -1) return;

	SAFE_CLOSE(data->spool_fd);
//	data->spool_fd = -1;
} /* spool_close() */

void spool_remove(struct session_t *data)
{
	spool_close(data);

	if (data->spool_exists) {
		if (unlink(data->spool_name) == -1)
			log_action(LOG_ERR, "%s:unlink(%s): %s", __FUNCTION__, data->spool_name, strerror(errno));

		data->spool_exists = 0;
	}
} /* spool_remove() */

int spool_create(struct session_t *data)
{
	int res;

	if (spool_max_size <= 0 || !data->spool_name) return 0;

	if (data->spool_fd != -1) SAFE_CLOSE(data->spool_fd);
	data->size = data->extra_size = 0;

	data->spool_fd = open(data->spool_name, O_WRONLY | O_CREAT | O_TRUNC, config.spool_perm);
	if (data->spool_fd == -1) {
//		res = errno;
		data->spool_exists = 0;
		log_action(LOG_ERR, "%s:open(%s): %s", __FUNCTION__, data->spool_name, strerror(errno));

		return (config.ignore_errors) ? 0 : -1;
	}

	data->spool_exists = 1;

	// data->time, pid procesu sa w nazwie pliku
	res = fdprintf(data->spool_fd, "%s: src=%s:%d, ident=%s, dst=%s:%d, trns=%d\r\n",
		config.spool_header, data->origin_str, ntohs(data->origin.sin_port), data->ident,
		data->target_str, ntohs(data->target.sin_port), data->transaction);

	if (res == -1) {
		res = errno;
		log_action(LOG_ERR, "SPOOL:INFO fdprintf() error: %s", strerror(errno));
		spool_remove(data);
		errno = res;
		if (!config.ignore_errors) return -1;
	} else {
		data->extra_size += res;
	}

	return 0;
} /* spool_create() */

int spool_write(struct session_t *data, void *buffer, int size)
{
	int res;

	if (!size) return 0;

	data->size += size;
	if (data->spool_fd == -1) return 0;

	while (size > 0) {
		if ((res = write(data->spool_fd, buffer, size)) == -1) {
			if (errno == EINTR) continue;
			log_action(LOG_ERR, "%s:write(%s): %s", __FUNCTION__, data->spool_name, strerror(errno));
			spool_remove(data);
			return -1;
		}

		// i tak go nie przeskanujemy bo za duzy, wiec nie ma sensu dalej spoolowac
		if (data->size > spool_max_size) {
			if (!IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ALWAYS))
				spool_remove(data);
			break;
		}

		size -= res;
		buffer += res;
	}

	return 0;
} /* spool_write() */


/*
 * spool_scan(data)
 * return: NULL = OK
 *         !NULL = error message
 *
 */

char* spool_scan(struct session_t *data)
{
	static char error[256];
	int scan_start, scan_time;
	int level;
	av_result scan_res;
	spam_result spam_res;
	double spam_score, cur_load;
	int do_unlink = !IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ALWAYS);
	char *scan_result_string = NULL;
	char *ret = NULL;


	/*
	 *	antivirus scanning
	*/

//	log_action(LOG_DEBUG, "about to SCAN, auth: 0x%0x", data->auth);

	SHARED_CONN_STATUS(state, CONN_SCAN);
	// skanowanie, jesli jest co skanowac
	if (data->spool_exists && (config.scan_max_size > 0) && (data->size <= config.scan_max_size)) {
		if (IS_FLAG_SET(data->auth, AUTH_FLAG_ACCEPTED) && IS_FLAG_SET(config.auth_skip, AUTH_SKIP_ANTIVIR)) {
			log_action(LOG_DEBUG, "SCAN:SKIPPED reason=auth");
			scan_res = SCAN_SKIPPED;
			scan_time = -1;
		} else {
			log_action(LOG_DEBUG, "DATA:SCANNING size=%d, src=%s, ident=%s",
				data->size, data->origin_str, data->ident);
			scan_start = time(NULL);
			SET_TIMEOUT(config.timeout_scanner);
			scan_res = av_scanner(data->spool_name, &scan_result_string);
			CLEAR_TIMEOUT();
			scan_time = time(NULL) - scan_start;
			data->virus_name = scan_result_string;
		}
	} else {
		scan_res = SCAN_SKIPPED;
		scan_time = -1;
	}

	if (scan_res == SCAN_OK) {
		// usun plik tymczasowy
		log_action(LOG_INFO, "SCAN:CLEAN size=%d, time=%d, src=%s, ident=%s",
			data->size, scan_time, data->origin_str, data->ident);
	} else if (scan_res == SCAN_SKIPPED) {
		log_action(LOG_INFO, "SCAN:SKIPPED size=%d, src=%s, ident=%s",
			data->size, data->origin_str, data->ident);
	} else if (scan_res == SCAN_VIRUS) {
		if (!scan_result_string) scan_result_string = config.msg_unknown_virus;
		if (IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_VIRUS)) do_unlink = 0;
		SHARED_STATS_INC(viruses);

		log_action(LOG_WARNING, "SCAN:VIRUS size=%d, time=%d, src=%s, ident=%s, virus=%s",
			data->size, scan_time, data->origin_str, data->ident, scan_result_string);

		snprintf(error, sizeof(error), "%s (%s)", config.msg_virus_found, scan_result_string);
		TERMINATE_STRING(error);
		ret = error;

		found(data, LOCK_ON_VIRUS, FOUND_VIRUS, scan_result_string);
	} else if (scan_res == SCAN_TIMEOUT) {
		if (IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ERROR)) do_unlink = 0;
		log_action(LOG_WARNING, "SCAN:TIMEOUT size=%d, time=%d, src=%s, ident=%s, result=%s",
			data->size, scan_time, data->origin_str, data->ident, scan_result_string);
		if (!config.ignore_errors) {
			snprintf(error, sizeof(error), "%s", config.msg_scanner_failed);
			TERMINATE_STRING(error);
			ret = error;
		}
	} else {
		// usun plik tymczasowy
		if (IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ERROR)) do_unlink = 0;
		log_action(LOG_ERR, "SCAN:FAILED size=%d, time=%d, src=%s, ident=%s, result=%s",
			data->size, scan_time, data->origin_str, data->ident, scan_result_string);
		if (!config.ignore_errors) {
			snprintf(error, sizeof(error), "%s", config.msg_scanner_failed);
			TERMINATE_STRING(error);
			ret = error;
		}
	}

	/*
	 *	antiSPAM scanning
	*/

	if ((config.spam_max_size > 0) && (ret == NULL)) {
		SHARED_CONN_STATUS(state, CONN_SPAM);
		if (is_load_above(config.spam_max_load, &cur_load) == 1) {
			log_action(LOG_INFO, "SPAM:SKIPPED size=%d, src=%s, ident=%s, load=%f",
				data->size, data->origin_str, data->ident, cur_load);
		} else if (IS_FLAG_SET(data->auth, AUTH_FLAG_ACCEPTED) && IS_FLAG_SET(config.auth_skip, AUTH_SKIP_ANTISPAM)) {
			log_action(LOG_DEBUG, "SPAM:SKIPPED reason=auth");
		} else if (data->spool_exists && (data->size <= config.spam_max_size)) {
			spam_score = 0.0;

			scan_start = time(NULL);
			SET_TIMEOUT(config.timeout_spam);
			spam_res = spam_scanner(data->spool_name, &spam_score);
			CLEAR_TIMEOUT();
			scan_time = time(NULL) - scan_start;

			if (spam_res == SPAM_OK) {
				spam_res = (spam_score >= config.spam_threshold) ? SPAM_YES : SPAM_NO;
				data->spam_score = spam_score;
			}

			if (spam_res == SPAM_YES) {
				scan_result_string = "FOUND";
				level = LOG_NOTICE;
				if (IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_SPAM)) do_unlink = 0;
				SHARED_STATS_INC(spams);

				data->found = FOUND_SPAM;
				if (IS_FLAG_SET(config.lock_on, LOCK_ON_SPAM)) {
					snprintf(error, sizeof(error), "%s [%f]", config.msg_spam_found, spam_score);
					TERMINATE_STRING(error);
					ret = error;

					lockfile_action(data, "SPAM");
				}
			} else if (spam_res == SPAM_NO) {
				scan_result_string = "CLEAN";
				level = LOG_INFO;
			} else if (spam_res == SPAM_SKIPPED) {
				scan_result_string = "SKIPPED";
				level = LOG_INFO;
			} else if (spam_res == SPAM_TIMEOUT) {
				scan_result_string = "TIMEOUT";
				level = LOG_WARNING;
				if (IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ERROR)) do_unlink = 0;
			} else {
				scan_result_string = "FAILED";
				level = LOG_ERR;
				if (IS_FLAG_SET(config.spool_leave_on, LEAVE_ON_ERROR)) do_unlink = 0;
			}

			log_action(level, "SPAM:%s size=%d, time=%d, src=%s, ident=%s, score=%f",
				scan_result_string, data->size, scan_time, data->origin_str,
				data->ident, spam_score);
		} else {
			log_action(LOG_INFO, "SPAM:SKIPPED size=%d, src=%s, ident=%s",
				data->size, data->origin_str, data->ident);
		}
	}

	if (do_unlink) spool_remove(data);
	return ret;
} /* spool_scan() */
