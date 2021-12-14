/*
 * 	lockfile.c
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
#define _LOCKFILE_C_

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
#include "action.h"
#include "util.h"
#include "lockfile.h"


struct option_enum lock_on_list[] = {
	{ "virus", LOCK_ON_VIRUS },
	{ "spam", LOCK_ON_SPAM },
	{ "maxhost", LOCK_ON_MAX_HOST },
	{ "maxident", LOCK_ON_MAX_IDENT },
	{ "dnsbl", LOCK_ON_DNSBL },
#ifdef USE_SPF
	{ "spf", LOCK_ON_SPF },
#endif
#ifdef USE_REGEX
	{ "regex", LOCK_ON_REGEX },
#endif
	{ "earlytalk", LOCK_ON_EARLYTALK },
	{ "ratelimit", LOCK_ON_RATELIMIT },
	{ "never", LOCK_NEVER },
	{ NULL }
};

/*
 * 	lockfile
*/

int lockfile_present(struct session_t *data)
{
	struct stat statinfo;
	char *tmp_ident;

	// lockfile bez identa? => sprawdzanie w innym miejscu
	if (EMPTY_STRING(data->lockfile)) return 0;

	// stat
	if (stat(data->lockfile, &statinfo) != 0) {
		// nie ma => ok
		if (errno == ENOENT) return 0;

		// problem innej natury
		log_action(LOG_CRIT, "LOCK:stat(%s): %s", data->lockfile, strerror(errno));
		return 0;
	}

	if (statinfo.st_uid == 0) {
		log_action(LOG_DEBUG, "LOCK:SAINT uid %" FORMAT_UID_T "!=%" FORMAT_UID_T ", src=%s, ident=%s [don't lock]",
			statinfo.st_uid, getuid(), data->origin_str, data->ident);
		return 0;
	}

	// jesli uplynal czas blokady to usun
	tmp_ident = EMPTY_STRING(data->ident) ? "-" : data->ident;

	if ((config.lock_duration == -1) || (time(NULL) - statinfo.st_mtime < config.lock_duration)) {
		log_action(LOG_DEBUG, "LOCK:LOCKED src=%s, ident=%s", data->origin_str, tmp_ident);
		return 1;
	} else {
		log_action(LOG_INFO, "LOCK:EXPIRED src=%s, ident=%s", data->origin_str, tmp_ident);
		unlink(data->lockfile);
		return 0;
	}
} /* lockfile_present() */

/*
 * creates lockfile
 * returns: -1=error, 0=created/disabled, 1=already exists
*/
int lockfile_touch(struct session_t *data, char *vir_name)
{
	int fd;

	if (!data->lockfile) return 0;

	fd = open(data->lockfile, O_CREAT|O_WRONLY|O_EXCL|O_NOCTTY|O_TRUNC, config.lock_perm);
	if (fd == -1) {
		if (errno == EEXIST) return 1;

		log_action(LOG_ERR, "LOCK:lockfile_touch:open(%s) error: %s", data->lockfile, strerror(errno));
		return -1;
	}

	fdprintf(fd, "%s\n", vir_name);
	SAFE_CLOSE(fd);

	log_action(LOG_DEBUG, "LOCK:CREATED (%s): %s", data->lockfile, vir_name);
	return 0;
} /* lockfile_touch() */


/*
 * when we've found some malicious activity
*/
void found(struct session_t *data, int flag, found_what found_what, char *cause)
{
	data->found = found_what;
	if (config.lock_duration && IS_FLAG_SET(config.lock_on, flag) && !lockfile_present(data))
		lockfile_action(data, cause);
}

void lockfile_action(struct session_t *data, char *cause)
{
	if (config.lock_duration && (config.lock_on != LOCK_NEVER)) {
		if (lockfile_touch(data, cause) < 1)
			user_action(data);
	} else {
		user_action(data);
	}
}


int lockfile_ident_present(struct session_t *data)
{
	char buf[sizeof(data->ident)];

	// lockfile bez identa? => sprawdzanie w innym miejscu
	if (!EMPTY_STRING(data->lockfile)) return lockfile_present(data);

	// usun niewygodne znaki z identa
	memcpy(buf, data->ident, sizeof(buf));
	untaint_for_filename(buf, sizeof(buf));

	if (asprintf(&data->lockfile, "%s/%s-%s", config.lock_path, data->origin_str, buf) == -1) {
		log_action(LOG_DEBUG, "LOCK:lockfile_ident_present:asprintf() error -1!");
		data->lockfile = NULL;
	}

	// sprawdz czy klient jest zablokowany
	if (config.lock_duration) {
//		log_action(LOG_DEBUG, "LOCK:DEBUG ident lock file [%s]", data->lockfile);
		return lockfile_present(data);
	} else {
		return 0;
	}
} /* lockfile_ident_present() */
