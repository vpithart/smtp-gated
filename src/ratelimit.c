/*
 * 	ratelimit.c
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
#define _RATELIMIT_C_

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "conffile.h"
#include "confvars.h"
#include "smtp-gated.h"
#include "util.h"
#include "ratelimit.h"


static uint32_t *config_table[] = {
	[RATELIMIT_INT_CONNECTIONS] = &config.ratelimit_connections,
	[RATELIMIT_INT_MESSAGES] = &config.ratelimit_messages,
	[RATELIMIT_INT_RECIPIENTS] = &config.ratelimit_recipients,
	[RATELIMIT_INT_BYTES] = &config.ratelimit_bytes,
	[RATELIMIT_INT_MAILFROM_REJECTS] = &config.ratelimit_mailfrom_rejects,
	[RATELIMIT_INT_RCPTTO_REJECTS] = &config.ratelimit_rcptto_rejects,
	[RATELIMIT_INT_AUTH_REJECTS] = &config.ratelimit_auth_rejects,
};

#define DESCRIPTION(a) [a] = #a
static char* config_names[] = {
	DESCRIPTION(RATELIMIT_INT_CONNECTIONS),
	DESCRIPTION(RATELIMIT_INT_MESSAGES),
	DESCRIPTION(RATELIMIT_INT_RECIPIENTS),
	DESCRIPTION(RATELIMIT_INT_BYTES),
	DESCRIPTION(RATELIMIT_INT_MAILFROM_REJECTS),
	DESCRIPTION(RATELIMIT_INT_RCPTTO_REJECTS),
	DESCRIPTION(RATELIMIT_INT_AUTH_REJECTS),
};

#if 0
static char *config_names[] = {
	[RATELIMIT_INT_CONNECTIONS] = "connections",
	[RATELIMIT_INT_MESSAGES] = "messages",
	[RATELIMIT_INT_RECIPIENTS] = "recipients",
	[RATELIMIT_INT_BYTES] = "bytes",
};
#endif


void ratelimit_done(struct session_t *data)
{
#ifdef HAVE_MMAP
	if (data->rate_map) {
		// msync(data->rate_map, data->rate_mapsize, MS_ASYNC);
		munmap(data->rate_map, data->rate_mapsize);
		data->rate_map = NULL;
	}
#endif
	SAFE_CLOSE(data->rate_fd);
}

int ratelimit_init(struct session_t *data)
{
	if (!config.ratelimit_expiration)
		return 0;

	char fn[1024];
	char ident_tmp[sizeof(data->ident)];
	if (data->ident && !EMPTY_STRING(data->ident)) {
		memcpy(ident_tmp, data->ident, sizeof(ident_tmp));
		untaint_for_filename(ident_tmp, sizeof(ident_tmp));
		snprintf(fn, sizeof(fn), "%s/%s-%s", config.ratelimit_path, data->origin_str, ident_tmp);
	} else {
		snprintf(fn, sizeof(fn), "%s/%s", config.ratelimit_path, data->origin_str);
	}
	TERMINATE_STRING(fn);

	if ((data->rate_fd = open(fn, O_CREAT|O_RDWR|O_NOCTTY, RATELIMIT_FILE_MODE)) == -1) {
		log_action(LOG_ERR, "ratelimit.open(%s): %s", fn, strerror(errno));
		return -1;
	}
	int size;

	struct ratelimit_record_t *rec;
	int res;

	struct stat st;
	if (fstat(data->rate_fd, &st) == -1) {
		log_action(LOG_ERR, "ratelimit.fstat(): %s", strerror(errno));
		SAFE_CLOSE(data->rate_fd);
		return -1;
	} else {
		size = st.st_size;
	}

	if (!S_ISREG(st.st_mode)) {
		log_action(LOG_ERR, "ratelimit.fstat(%s): not a regular file", fn);
		SAFE_CLOSE(data->rate_fd);
		return -1;
	}

	int i;
	/* create initial ratelimit record; inherit limits from config file */
	if (size < sizeof(*rec)) {
		size = sizeof(*rec);

		rec = calloc(1, size);
		rec->magic = RATELIMIT_MAGIC;
		rec->version = RATELIMIT_VERSION;
		rec->created = rec->last_cleared = rec->last_updated = time(NULL);
		rec->generation = config.ratelimit_generation;

		for (i=0; i<ARRAYSIZE(config_table); i++)
			rec->quota[i] = *config_table[i];

		if ((res = write(data->rate_fd, rec, size)) == -1) {
			log_action(LOG_ERR, "ratelimit.write: %s", strerror(errno));
			free(rec);
			return -1;
		}
		free(rec);
	}

	// read and verify magic&version before mmap()
	// if magic is incorrect, then leave the file alone, do not read it, do not write, do not use
	// ...


#ifdef HAVE_MMAP
	data->rate_mapsize = size;
	if ((data->rate_map = mmap(NULL, data->rate_mapsize, PROT_READ|PROT_WRITE, MAP_SHARED, data->rate_fd, 0)) == MAP_FAILED) {
		log_action(LOG_ERR, "ratelimit.mmap(): %s", strerror(errno));
		SAFE_CLOSE(data->rate_fd);
		return -1;
	}

	data->rate_dst = (struct ratelimit_ip_t *) ((char*) data->rate_map) + data->rate_map->dst_offset;
//	data->rate_helos = (struct ratelimit_md5_t *) ((char*) data->rate_map) + data->rate_map->helo_offset;
//	data->rate_mails = (struct ratelimit_md5_t *) ((char*) data->rate_map) + data->rate_map->mail_offset;

	if (data->rate_map->magic != RATELIMIT_MAGIC || data->rate_map->version != RATELIMIT_VERSION) {
		log_action(LOG_ERR, "ratelimit.verify(%s): invalid ratefile magic=%08x version=%08x", fn,
			data->rate_map->magic, data->rate_map->version);
		SAFE_CLOSE(data->rate_fd);
		munmap(data->rate_map, data->rate_mapsize);
		data->rate_map = NULL;
		return -1;
	}

	if (data->rate_map->generation < config.ratelimit_generation) {
		for (i=0; i<ARRAYSIZE(config_table); i++)
			data->rate_map->quota[i] = *config_table[i];
	}
#endif

	return 0;
}

int ratelimit_string(struct session_t *data, int what, char *str)
{
#warning TODO:ratelimit_string() not implemented
	return 0;
}

int ratelimit_ip(struct session_t *data, int what, uint32_t addr)
{
#ifndef HAVE_MMAP
#warning TODO:ratelimit_ip() not implemented
	return 0;
#else
	if (config.ratelimit_dst_expiration < 0)
		return 0;

	if (what != RATELIMIT_IP_DST)
		return -1;

	struct ratelimit_record_t *rec = data->rate_map;
	struct ratelimit_ip_t *dst = rec->dst;

	if (flock(data->rate_fd, LOCK_EX) == -1) {
		log_action(LOG_DEBUG, "ratelimit.flock(LOCK_EX): %s", strerror(errno));
		return -1;
	}

	time_t now = time(NULL);

	int i, found = 0, reject = 0, oldest = 0;
	uint32_t oldest_time = dst[0].last_used;
	for (i=0; i<ARRAYSIZE(rec->dst); i++) {
		if (dst[i].ip == addr) {
			dst[i].last_used = now;
			dst[i].usage_count++;
			found = 1;
			break;
		} else if (dst[i].ip != 0) {
			if (dst[i].last_used < oldest_time) {
				oldest = i;
				oldest_time = dst[i].last_used;
			}
		} else if (oldest_time) {
			oldest = i;
			oldest_time = 0;
		}
	}

	if (!found) {
		if (oldest_time + config.ratelimit_dst_expiration < now) {
			dst[oldest].ip = addr;
			dst[oldest].first_used = now;
			dst[oldest].last_used = now;
			dst[oldest].usage_count = 1;
		} else {
			// TODO: find the oldest and check if it has expired (days, weeks?)
			reject = 1;
		}
	}

	if (flock(data->rate_fd, LOCK_UN) == -1) {
		log_action(LOG_DEBUG, "ratelimit.flock(LOCK_UN): %s", strerror(errno));
		return -1;
	}

	return reject;
#endif
}

int ratelimit_uint(struct session_t *data, int what, uint32_t used)
{
	if (!config.ratelimit_expiration)
		return 0;

#ifdef HAVE_MMAP
	struct ratelimit_record_t *rec = data->rate_map;
	if (!rec) {
		log_action(LOG_DEBUG, "ratelimit not setup!");
		return -1;
	}
#else
#define	rec (&recbuf)
	struct ratelimit_record_t recbuf;
#endif

	time_t now = time(NULL);

	if (flock(data->rate_fd, LOCK_EX) == -1) {
		log_action(LOG_DEBUG, "ratelimit.flock(LOCK_EX): %s", strerror(errno));
		return -1;
	}

#ifndef HAVE_MMAP
	lseek(data->rate_fd, 0, SEEK_SET);
	int res = read(data->rate_fd, &recbuf, sizeof(recbuf));

	// validate
	if ((res != sizeof(recbuf)) || (rec->magic != RATELIMIT_MAGIC)) {
		memset(&recbuf, 0, sizeof(recbuf));
		rec->magic = RATELIMIT_MAGIC;
		rec->version = RATELIMIT_VERSION;
		rec->last_cleared = rec->last_updated = now;
	}
#endif

	if (rec->last_cleared + config.ratelimit_expiration < now) {
		log_action(LOG_DEBUG, "ratelimit.clear: cleared=%d updated=%d now=%ld",
			rec->last_cleared, rec->last_updated, now);
		rec->last_cleared = rec->last_updated = now;
		memset(rec->used, 0, sizeof(rec->used));
		memset(rec->tries, 0, sizeof(rec->tries));
	} else {
		if (used)
			rec->last_updated = now;
	}

	int i, reject;
	for (i=0, reject=0; i<ARRAYSIZE(config_table); i++) {
		// specific counter disabled?
		if (!rec->quota[i])
			continue;

		if (rec->used[i] <= rec->quota[i])
			continue;

		// specific counter over quota
		reject = 1;
		break;
	}

	// if the message will be rejected due to any counter being over quota, do not
	// add current value -- this would mess things up after admin has decided to
	// raise quota
	if (!reject && rec->quota[what]) {
		if (rec->used[what] + used <= rec->quota[what])
			rec->used[what] += used;
		else
			reject = 1;
	}

	/* tries always gets incremented */
	rec->tries[what] += rec->tries[what] + used;

#ifndef HAVE_MMAP
	lseek(data->rate_fd, 0, SEEK_SET);
	if ((res = write(data->rate_fd, &recbuf, sizeof(recbuf))) == -1)
		log_action(LOG_ERR, "ratelimit.write: %s", strerror(errno));
	else if (res < sizeof(recbuf))
		log_action(LOG_ERR, "ratelimit.write: short write sizeof(recbuf)=%d real=%d", sizeof(recbuf), res);
#endif

	if (flock(data->rate_fd, LOCK_UN) == -1) {
		log_action(LOG_DEBUG, "ratelimit.flock(LOCK_UN): %s", strerror(errno));
		return -1;
	}

#define RLD(x)	rec->used[x], rec->quota[x], rec->tries[x]
	log_action(LOG_DEBUG, "RATELIMIT:%s what=%d cleared=%d updated=%d connections=%u/%u/%u messages=%u/%u/%u recipients=%u/%u/%u bytes=%u/%u/%u",
		reject ? "REJECT" : "PASS", what,
		rec->last_cleared, rec->last_updated,
		RLD(RATELIMIT_INT_CONNECTIONS), RLD(RATELIMIT_INT_MESSAGES),
		RLD(RATELIMIT_INT_RECIPIENTS), RLD(RATELIMIT_INT_BYTES));

	return reject;
}

// console dump of ratefile
int ratelimit_dump(char *fn)
{
	struct ratelimit_record_t *rec;
	struct stat st;
	int fd, i;

	if ((fd = open(fn, O_RDONLY|O_NOCTTY, RATELIMIT_FILE_MODE)) == -1) {
		log_action(LOG_ERR, "ratelimit.open(%s): %s", fn, strerror(errno));
		return -1;
	}

	if (fstat(fd, &st) == -1) {
		log_action(LOG_ERR, "ratelimit.fstat(): %s", strerror(errno));
		SAFE_CLOSE(fd);
		return -1;
	}

	if ((rec = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		log_action(LOG_ERR, "ratelimit.mmap(): %s", strerror(errno));
		SAFE_CLOSE(fd);
		return -1;
	}

	printf("magic: 0x%08x\n", rec->magic);
	printf("version: 0x%08x\n", rec->version);
	printf("generation: 0x%08x\n", rec->generation);
	printf("created: %s\n", time2str(rec->created));
	printf("last cleared: %s\n", time2str(rec->last_cleared));
	printf("last updated: %s\n", time2str(rec->last_updated));
	printf("flags: %08x\n", rec->flags);

	printf("%2s %-32s %10s %10s %10s\n", "id", "name", "quota", "used", "tries");
	for (i=0; i<ARRAYSIZE(rec->quota); i++) {
		printf("%02u %-32s %10u %10u %10u\n", i,
			(i < ARRAYSIZE(config_names)) ? config_names[i] : "",
			rec->quota[i], rec->used[i], rec->tries[i]);
	}
	printf("%2s %-16s %10s %10s %10s\n", "id", "ip", "first", "last", "count");
	for (i=0; i<ARRAYSIZE(rec->dst); i++) {
		char ip[16];

		if (rec->dst[i].ip == 0 && i != 0)
			break;

		snprintf(ip, sizeof(ip), "%u.%u.%u.%u", NIPQUAD(rec->dst[i].ip));
		TERMINATE_STRING(ip);
		printf("%02u %-16s %10u %10u %10u\n", i,
			ip, rec->dst[i].first_used, rec->dst[i].last_used, rec->dst[i].usage_count);
	}

	if (munmap(rec, st.st_size) == -1)
		log_action(LOG_ERR, "ratelimit.munmap(): %s", strerror(errno));

	// closing fd does not unmap region
	SAFE_CLOSE(fd);

	return 0;
}








#if 0
static int rlid = -1;
static int manager_pid = -1;

// "7manager"
#define RATELIMIT_MANAGER_ID	0x76262437


int ratelimit_init()
{
	int res;


	if (rlid != -1) return;

	rlid = msgget(IPC_PRIVATE, S_IRWXU | IPC_CREAT);
	if (rlid == -1) {
		log_action(LOG_ERROR, "ratelimit:msgget(): %s", strerror(errno));
		return -1;
	}

	if ((manager_pid = fork()) == -1) {
		log_action(LOG_ERROR, "ratelimit:fork(): %s", strerror(errno));
		return -1;
	}

	if (manager_pid != 0) return 0;

	// signals setup?

	ratelimit_manager();
	exit(0);
}

int ratelimit_done()
{
	int ret = 0;

#if 0
	if (kill(manager_pid, SIGTERM) == -1) {
		log_action(LOG_ERROR, "ratelimit.kill: %s", strerror(errno));
		ret = -1;
	}
#endif

	if (msgctl(rlid, IPC_RMID, NULL) == -1) {
		log_action(LOG_ERROR, "ratelimit.msgctl(IPC_RMID): %s", strerror(errno));
		ret = -1;
	}

	return ret;
}


void ratelimit_sighandler(int sig)
{
}

// 'root' process
int ratelimit_manager()
{
	ssize_t size;
	struct ratelimit_request_t rlrq;
	struct ratelimit_response_t rlres;

	memset(rlrq, 0, sizeof(rlrq));
	memset(rlres, 0, sizeof(rlres));

	for (;;) {
		if ((size = msgrcv(rlid, (struct msgbuf *) &rlrq, sizeof(rlrq), RATELIMIT_MANAGER_ID, 0) == -1)) {
			if (errno == EINTR) continue;
			log_action(LOG_ERROR, "ratelimit.msgrcv(): %s", strerror(errno));
			break;
		}

		if (size != sizeof(rlrq)) {
			log_action(LOG_ERROR, "ratelimit.size_mismatch");
			continue;
		}

		// let's do the job
		hash = calc_hash(rlrq.ip, rlrq.ident);

		// ...
		rlres.type = rlrq.sender;
		rlres.verdict = 0;
		rlres.used = 0;
		rlres.limit = 10;
		rlres.period = 60;
		for (;;) {
			res = msgsnd(rlid, (struct msgbuf *) &rlres, sizeof(rlres), 0);
			if (res == -1 && errno == EINTR) continue;
			log_action(LOG_ERROR, "ratelimit.msgsnd(): %s", strerror(errno));
			break;
		}
	}

	// save_cache()
}
#endif
