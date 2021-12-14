/*
 * 	daemon.c
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
#define _DAEMON_C_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

//#include "confvars.h"
//#include "conffile.h"
#include "daemon.h"
#include "util.h"


static uid_t daemon_uid = -1;

/*
 * 	pid file
*/

int pidfile_create(char *pidfile)
{
	int fd;

	if (EMPTY_STRING(pidfile)) return 0;

	fd = open(pidfile, O_CREAT|O_WRONLY|O_EXCL|O_NOCTTY|O_TRUNC, PID_FILE_MODE);
	if (fd == -1) {
		log_action(LOG_CRIT, "Error creating pid file [%s]: %s", pidfile, strerror(errno));
		return -1;
	}
	fdprintf(fd, "%d\n", getpid());
	SAFE_CLOSE(fd);

	return 0;
}

int pidfile_remove(char *pidfile)
{
	if (EMPTY_STRING(pidfile)) return 0;
	if (strcmp(pidfile, "/") == 0) return 0;

	if (unlink(pidfile) != 0) {
		log_action(LOG_CRIT, "Error removing .pid file [%s]: %s", pidfile, strerror(errno));
		return -1;
	}

	return 0;
}

int pidfile_signal(int signum, char *pidfile)
{
	FILE *f;
	int bg_pid;

	f = fopen(pidfile, "r");
	if (!f) {
		fprintf(stderr, "Cannot open .pid file [%s]: %s\n", pidfile, strerror(errno));
		return -1;
	}

	if (fscanf(f, "%d", &bg_pid) != 1) {
		fclose(f);
		fprintf(stderr, "Cannot parse .pid file [%s]\n", pidfile);
		errno = EINVAL;
		return -1;
	}

	fclose(f);

//	fprintf(stderr, "Sending signal %d to process %d...\n", signal, bg_pid);
	if (kill(bg_pid, signum) != 0) {
		fprintf(stderr, "kill(%d, %d) error: %s\n", bg_pid, signum, strerror(errno));
		return -1;
	}

	return 0;
} /* pidfile_signal */


/*
 *	daemonize process
*/

#if 0
openlog();
fork();
setsid();
int util_chroot(char *path);
openlog() #2 ?
freopen(stdin/stdout/stderr, /dev/null);
pidfile(char *path);
renice(int level);
initgroup();
open_socket()?
setgid();
setuid();
#endif

/* char *workdir */
int daemonize(char *log_ident, int log_facility, int process_priority,
	char *chroot_path, char *pidfile, char *user, char *group, int flags)
{
	struct passwd *pw;
	struct group *grp;
	gid_t new_gid;
	int res;


	if (!foreground) {
		openlog(log_ident, LOG_PID, log_facility);
		log_action(LOG_INFO|LOG_ALWAYS, "starting up...");

		if  ((res = fork()) == -1) {
			log_action(LOG_CRIT, "fork(): %s", strerror(errno));
			return -1;
		}

		if (res) exit(0);

		if ((res = setsid()) == -1) {
			log_action(LOG_CRIT, "setsid(): %s", strerror(errno));
			return -1;
		}
	}

	if (!EMPTY_STRING(chroot_path)) {
		if (chdir(chroot_path) != 0) {
			log_action(LOG_CRIT, "chdir(%s): %s", chroot_path, strerror(errno));
			return -1;
		}
		if (chroot(chroot_path) != 0) {
			log_action(LOG_CRIT, "chroot(%s): %s", chroot_path, strerror(errno));
			return -1;
		}

		if (chdir("/") != 0) {
			log_action(LOG_CRIT, "chdir(\"/\"): %s", strerror(errno));
			return -1;
		}

		log_action(LOG_DEBUG, "chroot(%s) successful, reopening syslog", chroot_path);
		closelog();
		openlog(log_ident, LOG_PID, log_facility);
		log_action(LOG_DEBUG, "syslog reopened after chroot(%s), continuing", chroot_path);
	}

	if (!foreground) {
		if (!freopen("/dev/null", "r", stdin) || !freopen("/dev/null", "w", stdout) || !freopen("/dev/null", "w", stderr)) {
			log_action(LOG_CRIT, "freopen(stdxxx): %s", strerror(errno));
			return -1;
		}
	}


	if (pidfile_create(pidfile) != 0) return -1;

	if (process_priority) {
		if (setpriority(PRIO_PROCESS, 0, process_priority) < 0) {
			log_action(LOG_WARNING, "setpriority(%d) failed: %s", process_priority, strerror(errno));
		}
	}

	grp = NULL;

	if (!EMPTY_STRING(group)) {
		grp = getgrnam(group);

		if (grp == NULL) {
			log_action(LOG_CRIT, "getgrnam('%s') failed. no such group?", group);
			goto err_rem_pid;
		}
		if (setgid(grp->gr_gid) != 0) {
			log_action(LOG_CRIT, "setgid() failed: %s", strerror(errno));
			goto err_rem_pid;
		}
		log_action(LOG_INFO, "Changed GID to %d (%s)", grp->gr_gid, group);
	}

	if (!EMPTY_STRING(user)) {
		pw = getpwnam(user);
		daemon_uid = pw->pw_uid;

		if (pw == NULL) {
			log_action(LOG_CRIT, "getpwnam(%s) failed. no such user?", user);
			goto err_rem_pid;
		}
		new_gid = (grp != NULL) ? grp->gr_gid : pw->pw_gid;
		
		if (initgroups(pw->pw_name, new_gid) != 0) {
			log_action(LOG_CRIT, "initgroups() failed: %s", strerror(errno));
			goto err_rem_pid;
		}

		// change pid-file owner to new user id, we must be able to delete it
		if (!EMPTY_STRING(pidfile)) {
			if (chown(pidfile, daemon_uid, (gid_t) -1) != 0) {
				log_action(LOG_CRIT, "chown(%s) failed: %s", pidfile, strerror(errno));
				goto err_rem_pid;
			}
		}

		if ((grp == NULL) && (setgid(new_gid) != 0)) {
			log_action(LOG_CRIT, "setgid() for default group failed: %s", strerror(errno));
			goto err_rem_pid;
		}

		if (IS_FLAG_SET(flags, DAEMONIZE_SET_EUID_ONLY)) {
			if (seteuid(daemon_uid) != 0) {
				log_action(LOG_CRIT, "seteuid(%d) failed: %s", daemon_uid, strerror(errno));
				goto err_rem_pid;
			}
		} else {
			if (setuid(daemon_uid) != 0) {
				log_action(LOG_CRIT, "setuid(%d) failed: %s", daemon_uid, strerror(errno));
				goto err_rem_pid;
			}
		}

		log_action(LOG_INFO, "Changed UID to %d (%s)", daemon_uid, user);
	}

	return 0;

err_rem_pid:
	pidfile_remove(pidfile);
	return -1;
} /* daemonize() */


void debug_privileges(char *msg)
{
	uid_t r=-1, e=-1, s=-1;

	getresuid(&r, &e, &s);
	log_action(LOG_DEBUG, "%s: real=%d, effective=%d, saved=%d", msg, r, e, s);
}


int drop_privileges()
{
	int _err;
	uid_t r, e, s;

//	debug_privileges("drop_privileges().pre");
	if (daemon_uid == -1 && getuid() == 0) {
		log_action(LOG_WARNING, "WARNING:not dropping root privileges");
		return 0;
	}

	if (daemon_uid == getuid() && daemon_uid == geteuid())
		return 0;

	/* become root temporarily just to gain permissions to change real&effective uid */
	if (seteuid(0) == -1) {
		_err = errno;
		getresuid(&r, &e, &s);
		log_action(LOG_CRIT, "%s.seteuid(%d; real=%d, effective=%d, saved=%d): %s", __FUNCTION__, 0, r, e, s, strerror(_err));
		return -1;
	}

	if (setuid(daemon_uid) == -1) {
		_err = errno;
		getresuid(&r, &e, &s);
		log_action(LOG_CRIT, "%s.setuid(%d; real=%d, effective=%d, saved=%d): %s", __FUNCTION__, 0, r, e, s, strerror(_err));
		return -1;
	}

//	debug_privileges("drop_privileges().post");
	return 0;
}

int elevate_privileges()
{
	int _err;
	uid_t r, e, s;

	if (daemon_uid == -1)
		return 0;

	if (seteuid(0) < 0) {
		_err = errno;
		getresuid(&r, &e, &s);
		log_action(LOG_CRIT, "%s.seteuid(%d; real=%d, effective=%d, saved=%d): %s", __FUNCTION__, 0, r, e, s, strerror(_err));
		return -1;
	}
	return 0;
}

int lower_privileges()
{
	int _err;
	uid_t r, e, s;

	if (daemon_uid == -1)
		return 0;

	if (seteuid(daemon_uid) < 0) {
		_err = errno;
		getresuid(&r, &e, &s);
		log_action(LOG_CRIT, "%s.seteuid(%d; real=%d, effective=%d, saved=%d): %s", __FUNCTION__, daemon_uid, r, e, s, strerror(_err));
		return -1;
	}
	return 0;
}


