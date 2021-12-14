/*
 * 	ratelimit.h
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


#ifndef _RATELIMIT_H_
#define _RATELIMIT_H_


#ifndef _RATELIMIT_C_
#define EXTERN extern
#else
#define EXTERN
#endif


#define RATELIMIT_FILE_MODE	0600
#define RATELIMIT_MAGIC		0x72835464
#define RATELIMIT_VERSION	0x00010003
#define RATELIMIT_FILESIZE	8192

enum {
	/* integers */
	RATELIMIT_INT_CONNECTIONS = 0,	/* after accept() */
	RATELIMIT_INT_MESSAGES,		/* check before DATA, increase after DATA 2xx */
					/* maybe increase after DATA by successful RCPT TO count? */
	RATELIMIT_INT_RECIPIENTS,		/* check before RCPT TO, increase after RCPT TO 2xx */
	RATELIMIT_INT_BYTES,		/* check before DATA, increase after DATA 2xx */
	RATELIMIT_INT_MAILFROM_REJECTS,	/* after MAIL FROM 5xx */
	RATELIMIT_INT_RCPTTO_REJECTS,	/* after RCPT TO 5xx */
	RATELIMIT_INT_AUTH_REJECTS,	/* after AUTH RESPONSE 5xx */

	/* strings */
	RATELIMIT_STRING_HELO = 0,
	RATELIMIT_STRING_MAILFROM,

	/* IPs */
	RATELIMIT_IP_DST = 0,
};

enum {
	// file is configured per user (custom values), do not overwrite with defaults from smtp-gated.conf
	RATELIMIT_F_CUSTOM = 0x00000001,
};


struct ratelimit_md5_t {
	uint32_t hash[4];	// md5() of string: helo/ehlo, mail from, ...
	uint32_t first_used;
	uint32_t last_used;
	uint32_t usage_count;
};

struct ratelimit_ip_t {
	uint32_t ip;
	uint32_t first_used;
	uint32_t last_used;
	uint32_t usage_count;
};


// all integer fields are host-endian
struct ratelimit_record_t {
	uint32_t magic;				// magic key
	uint32_t version;			// general structure of file
	uint32_t generation;			// generation of particular file; increased if tables are resized
	uint32_t created;			// time of creation
	uint32_t last_cleared;			// time of last clear of counters
	uint32_t last_updated;			// time of last update
	uint32_t flags;				// unused

	// counters
	uint32_t quota[16];			// configured quota, inherited from main config file
	uint32_t used[16];			// used quota for particular counter, will not get over configured limit
	uint32_t tries[16];			// counter for tries of use and over-use for particular counter, unlimited

	// IP table
	struct ratelimit_ip_t dst[64];		// target IP

	// string tables
	uint32_t dst_offset, dst_count;		// dst IPs, payload-offset, array[] size
	uint32_t string_table_offset[4];	// RATELIMIT_STRING_* array offset (relative to file seek 0)
	uint32_t string_table_count[4];		// RATELIMIT_STRING_* array size

	uint8_t payload[0];

	struct ratelimit_md5_t helo[64];	// HELO/EHLO
	struct ratelimit_md5_t from[64];	// MAIL FROM

	// HELO/EHLO with count and first/last used time
	// MAIL FROMs with count first/last used time
	// destination IPs with count and first/last used time
} __attribute__ ((packed));

#if 0
enum { RATELIMIT_NONE, RATELIMIT_GET } ratelimit_operation;

typedef struct ratelimit_request_t {
	long type;	// struct msgbuf.type
	
	int sender;	// msg type
	struct sockaddr_in ip;
	char ident[IDENT_SIZE+1];
};

typedef struct ratelimit_response_t {
	long type;	// struct msgbuf.type

	int verdict;
	int used;
	int limit;
	int period;
};

EXTERN int ratelimit_init();
EXTERN ini ratelimit_done();
#endif

EXTERN int ratelimit_init(struct session_t *data);
EXTERN void ratelimit_done(struct session_t *data);
EXTERN int ratelimit_uint(struct session_t *data, int what, uint32_t used);
EXTERN int ratelimit_string(struct session_t *data, int what, char *str);
EXTERN int ratelimit_ip(struct session_t *data, int what, uint32_t addr);
EXTERN int ratelimit_dump(char* fn);


#undef EXTERN

#endif

