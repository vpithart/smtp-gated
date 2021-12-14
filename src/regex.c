/*
 * 	regex.c
 *
 * 	Copyright (C) 2004-2005 Bart³omiej Korupczynski <bartek@klolik.org>
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
#define _REGEX_C_

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include <netinet/in.h>
#include <netdb.h>

#ifdef HAVE_PCRE_H
#include <pcre.h>
#else
#ifdef HAVE_PCRE_PCRE_H
#include <pcre/pcre.h>
#endif
#endif

#include "conffile.h"
#include "smtp-gated.h"
#include "confvars.h"
#include "util.h"
#include "regex.h"


static pcre *regex_enforce_helo = NULL;
static pcre *regex_reject_helo = NULL;
static pcre *regex_enforce_mail_from = NULL;
static pcre *regex_reject_mail_from = NULL;
static pcre *regex_enforce_rcpt_to = NULL;
static pcre *regex_reject_rcpt_to = NULL;

static pcre_extra *study_enforce_helo = NULL;
static pcre_extra *study_reject_helo = NULL;
static pcre_extra *study_enforce_mail_from = NULL;
static pcre_extra *study_reject_mail_from = NULL;
static pcre_extra *study_enforce_rcpt_to = NULL;
static pcre_extra *study_reject_rcpt_to = NULL;


const char* regex_version()
{
	static char version[128];

	snprintf(version, sizeof(version), "libpcre %s", pcre_version());
	TERMINATE_STRING(version);

	return version;
}


static int compile_study(char *expr, pcre** regex, pcre_extra **extra)
{
	const char *errstr;
	int erroffs;

	FREE_NULL(*regex);
	FREE_NULL(*extra);

	if (EMPTY_STRING(expr)) return 0;

	if ((*regex = pcre_compile(expr, 0, &errstr, &erroffs, NULL)) == NULL) {
		log_action(LOG_ERR, "pcre_compile expr=[%s] error=[%d]: %s", expr, erroffs, errstr);
		return -1;
	}

	*extra = pcre_study(*regex, 0, &errstr);
	if (errstr) {
		log_action(LOG_ERR, "pcre_study expr=[%s] error=[%s]", expr, errstr);
		return -1;
	}

	return 0;
}


int regex_parse()
{
	if (compile_study(config.regex_enforce_helo, &regex_enforce_helo, &study_enforce_helo))
		return -1;

	if (compile_study(config.regex_reject_helo, &regex_reject_helo, &study_reject_helo))
		return -1;

	if (compile_study(config.regex_enforce_mail_from, &regex_enforce_mail_from, &study_enforce_mail_from))
		return -1;

	if (compile_study(config.regex_reject_mail_from, &regex_reject_mail_from, &study_reject_mail_from))
		return -1;

	if (compile_study(config.regex_enforce_rcpt_to, &regex_enforce_rcpt_to, &study_enforce_rcpt_to))
		return -1;

	if (compile_study(config.regex_reject_rcpt_to, &regex_reject_rcpt_to, &study_reject_rcpt_to))
		return -1;

	return 0;
}

static int regex_match(char *str, pcre *comp, pcre_extra *extra, char *description)
{
	int res;

	if ((res = pcre_exec(comp, extra, str, strlen(str), 0, 0, NULL, 0)) < 0 && res != PCRE_ERROR_NOMATCH) {
		log_action(LOG_ERR, "REGEX:ERROR condition=%s result=%d", description, res);
		return -1;
	}

	log_action(LOG_DEBUG, "REGEX:%s condition=%s string=%s", (res == 0) ? "MATCH" : "NO-MATCH", description, str);

	// no match
	if (res == PCRE_ERROR_NOMATCH) return 0;
	// match found
	if (res == 0) return 1;

	// we shouldn't get here...
	BUG("pcre_exec unknown result=%d", res);
	return 0;
}

#define REGEX_MATCH(str, cond, study) regex_match(str, cond, study, #cond)

int regex_check_helo(char *str)
{
	int res;

//	log_action(LOG_DEBUG, "regex_check_helo([%s], [%s])", str, config.regex_helo);
	if (regex_enforce_helo) {
		res = REGEX_MATCH(str, regex_enforce_helo, study_enforce_helo);
		if (res != 1) return 0;
	}
	if (regex_reject_helo) {
		res = REGEX_MATCH(str, regex_reject_helo, study_reject_helo);
		if (res != 0) return 0;
	}

	return 1;
}

int regex_check_mail_from(char *str)
{
	int res;

//	log_action(LOG_DEBUG, "regex_check_mail_from([%s], [%s])", str, config.regex_mail_from);
	if (regex_enforce_mail_from) {
		res = REGEX_MATCH(str, regex_enforce_mail_from, study_enforce_mail_from);
		if (res != 1) return 0;
	}
	if (regex_reject_mail_from) {
		res = REGEX_MATCH(str, regex_reject_mail_from, study_reject_mail_from);
		if (res != 0) return 0;
	}

	return 1;
}

int regex_check_rcpt_to(char *str)
{
	int res;

//	log_action(LOG_DEBUG, "regex_check_rcpt_to([%s], [%s])", str, config.regex_rcpt_to);
	if (regex_enforce_rcpt_to) {
		res = REGEX_MATCH(str, regex_enforce_rcpt_to, study_enforce_rcpt_to);
		if (res != 1) return 0;
	}
	if (regex_reject_rcpt_to) {
		res = REGEX_MATCH(str, regex_reject_rcpt_to, study_reject_rcpt_to);
		if (res != 0) return 0;
	}

	return 1;
}


