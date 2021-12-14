/*
 *	scan.c
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

#include <stdio.h>
#include <unistd.h>
#include <sys/un.h>
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define _SCAN_C_
#include "confvars.h"
#include "conffile.h"
#include "smtp-gated.h"
#include "scan.h"
#include "util.h"

#ifdef SCANNER_LIBDSPAM
#ifdef HAVE_LIBDSPAM_H
#include <libdspam.h>
#elif HAVE_DSPAM_LIBDSPAM_H
#include <dspam/libdspam.h>
#endif
//#include <dspam/libdspam.h>
#endif

#ifdef SCANNER_MKSD
#ifdef HAVE_LIBMKSD_H
#include <libmksd.h>
#else
#include "libmksd.h"
#endif
#endif

struct option_enum antivirus_type_list[] = {
	{ "off", AV_NONE },
//	{ "script", AV_SCRIPT },
//	{ "pipe", AV_PIPE },
	{ "clamd", AV_CLAMD },
#ifdef SCANNER_MKSD
	{ "mksd", AV_MKSD },
#endif
#ifdef SCANNER_MKS32
	{ "mks32", AV_MKS32 },
#endif
//	{ "drweb", AV_DRWEB },
	/* <END OF AV-ENUM> */
	{ NULL, -1 }
};

struct option_enum antispam_type_list[] = {
	{ "off", AS_NONE },
//	{ "script", AS_SCRIPT },
//	{ "pipe", AS_PIPE },
	{ "spamassassin", AS_SPAMASSASSIN },
#ifdef SCANNER_LIBDSPAM
	{ "libdspam", AS_LIBDSPAM },
#endif
	/* <END OF AS-ENUM> */
	{ NULL, -1 }
};


#if 0
static scan_result_str(scan_result_t res)
{
	switch (res) {
		case SCAN_INVALID: return "INVALID";
		case SCAN_FAILED: return "FAILED";
		case SCAN_TIMEOUT: return "TIMEOUT";
		case SCAN_SKIPPED: return "SKIPPED";
		case SCAN_PASS: return "PASS";
		case SCAN_REJECT: return "REJECT";
		default: return "!BUG!";
	}
}
#endif


#if 0
static void post_fork_cleanup()
{
	// close fd's & others
}
#endif

/*
 *	all scanners must be prepared to receive EINTR (which means timeout)
 *	and check 'timedout' variable
*/


/*
 *	SpamAssassin
*/

static spam_result as_spamassassin(char *filename, double *score)
{
	int sock = -1;
	int file, pos;
	ssize_t res, len;
	char buf[32768];
	char version[32];
	double temp_thr;
	struct stat st;
	long int size;


	// spool open
	if ((file = open(filename, O_RDONLY)) == -1) {
		log_action(LOG_CRIT, "spamd:open(%s): %s", filename, strerror(errno));
		goto fail;
	}

	if (fstat(file, &st) == -1) {
		log_action(LOG_CRIT, "spamd:stat(%s): %s", filename, strerror(errno));
		goto fail;
	}

	/* BSD compat */
	size = st.st_size;

	if ((sock = connect_path(config.antispam_path)) == -1) {
		log_action(LOG_CRIT, "spamd:connect_path(%s) error: %s", config.antispam_path, strerror(errno));
		goto fail;
	}

	// lookup.c:71: warning: passing arg 2 of `getsockname' from incompatible pointer type
	if (fdprintf(sock, "CHECK SPAMC/1.2\r\nContent-length: %ld\r\n\r\n", size) == -1) {
		log_action(LOG_CRIT, "spamd:fdprintf(sock) failed: %s", strerror(errno));
		goto fail;
	}

#ifdef USE_SHARED_MEM
	set_dump_state(CONN_SPAM1);
#endif

	for (;;) {
		if (timedout) {
			log_action(LOG_WARNING, "spamd:read(file):timeout");
			errno = ETIMEDOUT;
			goto fail;
		}

		if ((len = read(file, buf, sizeof(buf))) == -1) {
			// SIGALRM sets timedout flags
			if (errno == EINTR) continue;
			
			log_action(LOG_CRIT, "spamd:read(file) error: %s", strerror(errno));
			goto fail;
		}

		if (len == 0) break;

//		if ((res = send(sock, buf, len, 0)) != len) {
		for (pos=0;;) {
			if (timedout) {
				log_action(LOG_WARNING, "spamd:write(sock):timeout");
				errno = ETIMEDOUT;
				goto fail;
			}
			if ((res = write(sock, buf+pos, len)) == -1) {
				if (errno == EINTR) continue;

				log_action(LOG_CRIT, "spamd:write(sock) error: %s", strerror(errno));
				goto fail;
			}

			if (res == 0) break;

			len -= res;
			if (len == 0) break;
			pos += res;
		}
	}

	SAFE_CLOSE(file);
//	file = -1;
	shutdown(sock, SHUT_WR);

#ifdef USE_SHARED_MEM
	set_dump_state(CONN_SPAM2);
#endif
	memset(buf, 0, sizeof(buf));
	for (pos=0;;) {
		if (timedout) {
			log_action(LOG_WARNING, "spamd:read(sock) timeout");
			errno = ETIMEDOUT;
			break;
		}
		if ((res = read(sock, buf+pos, sizeof(buf)-pos)) == -1) {
			if (errno == EINTR) continue;

			log_action(LOG_CRIT, "spamd:read(sock) error: %s", strerror(errno));
			goto fail;
		}

		if (res == 0) break;
		pos += res;
	}

	TERMINATE_STRING(buf);
	SAFE_CLOSE(sock);
//	sock = -1;

//	log_action(LOG_DEBUG, "spamd: returned [%s]", buf);

	if (sscanf(buf, "SPAMD/%30s 0 EX_OK\r\nSpam: %*s ; %lf / %lf \r\n", version, score, &temp_thr) != 3) {
		log_action(LOG_CRIT, "spamd:sscanf() cannot parse output [%s]", buf);
		goto fail;
	}

//	alahutdoown
	//	m(0);
//	return (*score > spam_threshold) ? SPAM_YES : SPAM_NO;
	return SPAM_OK;

fail:
	res = (errno == EINTR || errno == ETIMEDOUT) ? SPAM_TIMEOUT : SPAM_FAILED;
//	alarm(0);
	if (file != -1) SAFE_CLOSE(file);
	if (sock != -1) SAFE_CLOSE(sock);

	return res;
}

#ifdef SCANNER_LIBDSPAM
static spam_result as_libdspam(char *filename, double *score)
{
	DSPAM_CTX *dsc;
	int res;
	struct stat st;
	char *message;
	int pos, size, file;


	if ((dsc = dspam_init(config.set_user, config.set_group, config.dspam_storage, DSM_PROCESS, 0)) == NULL) {
		errno = EFAILURE;
		return SPAM_FAILED;
	}

#ifdef USE_SHARED_MEM
	set_dump_state(CONN_SPAM1);
#endif

	if ((file = open(filename, O_RDONLY)) == -1) {
		log_action(LOG_CRIT, "libdspam:open(%s): %s", filename, strerror(errno));
		goto fail;
	}

	if (fstat(file, &st) == -1) {
		log_action(LOG_CRIT, "libdspam:stat(%s): %s", filename, strerror(errno));
		goto fail;
	}

	message = malloc(st.st_size + 1);
	memset(message, '\0', st.st_size);
	for (pos=0;;) {
		if ((size = read(file, message+pos, st.st_size-pos)) == -1) {
			// timeout
			if (errno == EINTR) goto fail;
			log_action(LOG_CRIT, "libdspamd:read(file) error: %s", strerror(errno));
			goto fail;
		}
		pos += size;
		if (size == 0) break;
	}

	close(file);
	message[st.st_size] = '\0';

#ifdef USE_SHARED_MEM
	set_dump_state(CONN_SPAM2);
#endif

	res = dspam_process(dsc, message);
	switch (res) {
		case DSR_ISSPAM:
			res = SPAM_YES;
			*score = 10;
			break;
		case DSR_ISINNOCENT:
#ifdef DSR_ISWHITELISTED
		case DSR_ISWHITELISTED:
#endif
			res = SPAM_NO;
			*score = 0;
			break;
		case EINVAL:
		case EUNKNOWN:
		case EFILE:
		case ELOCK:
		case EFAILURE:
		default:
			errno = res;
			res = SPAM_FAILED;
			break;
	}

	dspam_destroy(dsc);
	CLEAR_TIMEOUT();
	return res;

fail:
	res = (errno == EINTR || errno == ETIMEDOUT) ? SPAM_TIMEOUT : SPAM_FAILED;
	CLEAR_TIMEOUT();
	return res;
}
#endif

/*
 *	Clam Antivirus daemon
*/

static av_result av_clamd(char *filename, char **result)
{
	static char buf[4800];
	int sock;
	ssize_t res;
	size_t pos;
	char *p;


	if ((sock = connect_path(config.antivirus_path)) == -1) {
		log_action(LOG_CRIT, "clamd:connect_path(%s) error: %s", config.antivirus_path, strerror(errno));
		goto fail;
	}

	if (fdprintf(sock, "SCAN %s\n", filename) == -1) {
		if (errno != EINTR && errno != ETIMEDOUT)
			log_action(LOG_CRIT, "clamd:fdprintf(SCAN...): %s", strerror(errno));
		goto fail;
	}

#ifdef USE_SHARED_MEM
	set_dump_state(CONN_SCAN1);
#endif

	// konieczne!
//	memset(buf, '\0', sizeof(buf));
	for (pos=0;;) {
		if (timedout) {
			CLEAR_TIMEOUT();
//			log_action(LOG_ERR, "clamd:timeout");
			errno = ETIMEDOUT;
			goto fail;
		}

		if ((res = read(sock, buf+pos, sizeof(buf)-pos)) == -1) {
			if (errno == EINTR) continue;
			log_action(LOG_CRIT, "clamd:read(sock) error: %s", strerror(errno));
			goto fail;
		}

		if (res == 0) break;
		pos += res;
	}

//	alarm(0);
	SAFE_CLOSE(sock);
//	sock = -1;

	if (pos >= sizeof(buf)) {
		log_action(LOG_CRIT, "clamd:buffer to small");
		return SCAN_FAILED;
	}
	buf[pos-1] = '\0';
	TERMINATE_STRING(buf);

/*
	"%s: %s FOUND\n", filename, virname
	"%s: %s ERROR\n", filename, cl_strerror(ret)
	"%s: OK\n"
	"%s: Empty file\n", filename
*/
	// usuwamy '\n' z konca
	if ((p = strrchr(buf, '\n'))) {
		*p = '\0';
	}

	// szukamy pierwszego dwukropka
	p = strchr(buf, ':');
	if (p == NULL) {
		log_action(LOG_CRIT, "clamd:parse malformed response (%s)", buf);
		return SCAN_FAILED;
	}

	p++;
	while (*p == ' ') p++;
	*result = p;

	// szukamy ostatniej spacji
	p = strrchr(buf, ' ');
	if (p == NULL) {
		log_action(LOG_CRIT, "clamd:parse malformed response (%s)", buf);
		return SCAN_FAILED;
	}
	*p = '\0';
	p++;

	if (strcmp(p, "ERROR") == 0) return SCAN_FAILED;
	if (strcmp(p, "FOUND") == 0) return SCAN_VIRUS;
	if (strcmp(p, "OK") == 0) {
		*result = NULL;
		return SCAN_OK;
	}

	log_action(LOG_WARNING, "clamd:returned (%s %s %s)", buf, *result, p);
	return SCAN_OK;

fail:
	res = (errno == EINTR || errno == ETIMEDOUT) ? SCAN_TIMEOUT : SCAN_FAILED;
//	alarm(0);
	if (sock != -1) SAFE_CLOSE(sock);

	return res;
}



/*
 * 	mks_vir daemon
*/

#ifdef SCANNER_MKSD
static av_result av_mksd(char *filename, char **result)
{
	char opts[] = "S\0";
	static char buf[4200];
	char *cur;
	int code;


	memset(buf, '\0', sizeof(buf));

	if (mksd_connect() < 0) {
		log_action(LOG_CRIT, "MKSD: connect failed");
		return SCAN_FAILED;
	}


	memset(buf, 0, sizeof(buf));
	if (mksd_query(filename, opts, buf) < 0) {
		log_action(LOG_CRIT, "MKSD:query failed");
		return SCAN_FAILED;
	}

	mksd_disconnect();

	if (memcmp(buf, "OK ", 3) == 0) return SCAN_OK;
	if (memcmp(buf, "CLN ", 4) == 0) return SCAN_OK;
	if (memcmp(buf, "DEL ", 4) == 0) return SCAN_OK;

	cur = NULL;
	code = 0;
	if (memcmp(buf, "ERR ", 4) == 0) {
		cur = buf + 4;
		code = SCAN_FAILED;
	}

	if (memcmp(buf, "VIR ", 4) == 0) {
		cur = buf + 4;
		code = SCAN_VIRUS;
	}

	if (cur != NULL) {
		*result = cur;
		for (;; cur++) {
			if (*cur == ' ') break;
			if (*cur == '\0') break;

			if (cur+1 >= buf+sizeof(buf)) break;
		}
		*cur = '\0';

		return code;
	}

	buf[16] = '\0';
	log_action(LOG_ERR, "MKSD:unknown result [%s]", buf);
	return SCAN_FAILED;

}
#endif


/*
 *	mks_vir stand-alone
*/

#ifdef SCANNER_MKS32
#error SIGCHLD removed from signal handling
static av_result av_mks32(char *filename, char **name)
{
	struct timeval tv;
	int pid, res;
	char *arg[] = { antivirus_path, "--exit", filename, NULL};
	char *env[] = { "PATH=/usr/local/bin:/usr/bin:/bin", NULL };


	pid = fork();
	if (pid < 0) {
		log_action(LOG_CRIT, "Fork failed: %s", strerror(errno));
		return SCAN_FAILED;
	}

	child_status = 0;

	if (!pid) { // dzieciak
		post_fork_cleanup();
		(void) drop_privileges();
		res = execve(antivirus_path, arg, env);

		// nie powinno tu dotrzec
		log_action(LOG_CRIT, "execve failed: %s", strerror(errno));
		exit(255);
	} else {
		tv.tv_sec = timeout_scanner;
		tv.tv_usec = 0;
		res = select(0, NULL, NULL, NULL, &tv);
		if (res == 0) {
			// timeout

			kill(pid, SIGTERM);
			return SCAN_TIMEOUT;
		}

		// EINTR <= SIGCHLD
		if (errno != EINTR) {
			log_action(LOG_ERR, "select: %s", strerror(errno));
			return SCAN_FAILED;
		}
	}

	child_reaper();
	if (WIFEXITED(child_status) == 0) return SCAN_FAILED;
	
	res = WEXITSTATUS(child_status);
	if (res > 0x07) return SCAN_FAILED;
	if (res & 0x07) return SCAN_VIRUS;

	if (res == 0) return SCAN_OK;
	return SCAN_FAILED;
}
#endif


/* <END OF SCANNERS> */


/*
 *	scanner stubs
*/

av_result av_scanner(char *filename, char **result)
{
	*result = NULL;

	switch (config.antivirus_type) {
		case AV_NONE:
			return SCAN_SKIPPED;
		case AV_CLAMD:
			return av_clamd(filename, result);
#ifdef SCANNER_MKSD
		case AV_MKSD:
			return av_mksd(filename, result);
#endif
#ifdef SCANNER_MKS32
		case AV_MKS32:
			return av_mks32(filename, result);
#endif
		/* <END OF AV-HOOK> */
		default:
			*result = config.msg_unknown_scanner;
			return SCAN_FAILED;
	}
}

spam_result spam_scanner(char *filename, double *score)
{
//	*score = 0.0;
	
	switch (config.antispam_type) {
		case AS_NONE:
			return SPAM_SKIPPED;
		case AS_SPAMASSASSIN:
			return as_spamassassin(filename, score);
#ifdef SCANNER_LIBDSPAM
		case AS_LIBDSPAM:
			return as_libdspam(filename, score);
#endif
		/* <END OF AS-HOOK> */
		default:
			return SPAM_FAILED;
	}
}


/*
	tbf + penalty
	
	non-header/body:
		CHECK:REJECT engine=load load=2.1 of=0.8
		CHECK:REJECT engine=host count=10 of=10
		CHECK:REJECT engine=ident count=4 of=4
		CHECK:REJECT engine=rate count=10 of=10 per=1m
		CHECK:REJECT engine=regex no-match=helo
		CHECK:REJECT engine=auth flags=no-auth of=auth-required
		CHECK:REJECT engine=spf domain=yahoo.com result=fail
	header:
		HEADER:REJECT engine=regex match=header
	body:
		BODY:REJECT engine=clamd found=Eicar
		BODY:REJECT engine=spamd score=9.0
		BODY:REJECT engine=regex match=body
*/

/*
 * check_before_fork(): maxhost
 * check_after_fork():
 * check_before_connect(): maxident
 * check_after_connect(): dnsbl+!skip_auth
 * check_before_helo(): regex_helo
 * check_after_helo(): 
 * check_before_mailfrom(): spf, regex_mailfrom, dnsbl+skip_auth
 * check_after_mailfrom(): 
 * check_before_rcptto(): regex_rcptto
 * check_after_rcptto():
 * check_before_data():
 * check_after_data(): antivirus, antispam, regex_body
 * check_header():
 * check_body(): 
 *
 * %s:SCAN_XXX
*/


