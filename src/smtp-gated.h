/*
 *	smtp-gated.h
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


#ifndef _SMTP_GATED_H_
#define _SMTP_GATED_H_

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_ERR_H
#include <err.h>
#endif
#include <syslog.h>
#include <signal.h>

#ifndef _SMTP_GATED_C_
#define EXTERN extern
#else
#define EXTERN
#endif

/*
 *	hard configuration
*/

// #define SPAM_SCORE_NONE			-1000
#define PIPELINE_SIZE_MIN			16
#define SLOT_HASH_THRESHOLD			16

// don't change!!
#define RCPTS_ONE_TIME				2

/*
 *	logging options
*/
#define LOG_MAIL_NONE				0x0000
#define LOG_MAIL_ACCEPTED			0x0001
#define LOG_MAIL_REJECTED			0x0002
#define LOG_MAIL_BASE64				0x0004


/*
 *	SMTP AUTH request
*/
#define AUTH_REQUIRE_NO				0x0000
#define AUTH_REQUIRE_IFSUPPORTED	0x0001
#define AUTH_REQUIRE_MANDATORY		0x0002

#define AUTH_FLAG_SUPPORTED			0x0001
#define AUTH_FLAG_ACCEPTED			0x0002
#define AUTH_FLAG_REJECTED			0x0004

#define AUTH_SKIP_NONE				0x0000
#define AUTH_SKIP_ANTIVIR			0x0001
#define AUTH_SKIP_ANTISPAM			0x0002
#define AUTH_SKIP_REGEX				0x0004
#define AUTH_SKIP_DNSBL				0x0008
#define AUTH_SKIP_DIRECT			0x0010

/* log traffic to STDOUT */
#define FORE_LOG_TRAFFIC			0x0001
/* signal parent PID after startup or HUP */
#define FORE_DEBUG_STAGE			0x0002
/* do not fork (debugging) */
#define FORE_SINGLE					0x0004


/*
 * 	macros
*/

#define SET_TIMEOUT(x)				{ timedout = 0; (void) alarm(x); }
#define CLEAR_TIMEOUT()				{ timedout = 0; (void) alarm(0); }

#ifndef VERSION
#error config.h not included
#endif

#ifdef USE_SHARED_MEM
#define SHARED_CONN_STATUS(x, y)	{ connections[child_slot].x = (y); }
#define SHARED_CONN_FLAGS_OR(y)		{ connections[child_slot].flags |= (y); }
#define SHARED_STATS_INC(x)			{ stats->x++; }
#else
#define SHARED_CONN_STATUS(x, y)
#define SHARED_CONN_FLAGS_OR(x, y)
#define SHARED_STATS_INC(x)
#endif


#define NR(generic)					(struct response_code) {generic, -1, -1}
#define ER(generic,subject,detail)	(struct response_code) {generic, subject, detail}
#define CONN_REJ_ER					(struct response_code) {CONN_REJ_CODE,3,0}


/*
 *	SMTP commands (~verbs)
*/

typedef enum {
	COMMAND_NONE = 0,
	COMMAND_GREETING,
	COMMAND_OTHER,
//	COMMAND_STOLEN,

	COMMAND_HELO, COMMAND_EHLO,
	COMMAND_RSET,
	COMMAND_STARTTLS,
	COMMAND_AUTH,
	COMMAND_MAIL, COMMAND_RCPT,
	COMMAND_DATA, COMMAND_DATA_ACK,
	COMMAND_BDAT,
	COMMAND_QUIT,
	COMMAND_XCLIENT
} smtp_command_t;


/*
 *	SMTP DATA state
*/
typedef enum {
	GOING_NONE = 0,
	GOING_HEADER,
	GOING_BODY,
	GOING_AUTH
} data_phase;

/*
 *	connections states (conn_states[] index)
*/
typedef enum {
    CONN_START = 0, CONN_HELO,
	CONN_IDENT, CONN_CONNECT, CONN_PRE,
	CONN_SPF,
	CONN_DNSBL,
	CONN_DATA, CONN_BDAT, CONN_DIRECT,
	CONN_SCAN, CONN_SCAN1, CONN_SCAN2, CONN_SPAM, CONN_SPAM1, CONN_SPAM2,
	CONN_POST, CONN_RSET, CONN_QUIT
} conn_state;


/*
 *	found virus or found spam enum
*/
typedef enum {
	FOUND_NONE = 0,
	FOUND_VIRUS,
	FOUND_SPAM,
	FOUND_MAX_HOST,
	FOUND_MAX_IDENT,
	FOUND_DNSBL,
	FOUND_SPF,
	FOUND_REGEX_HELO_EHLO,
	FOUND_REGEX_MAIL_FROM,
	FOUND_REGEX_RCPT_TO,
	FOUND_EARLYTALK,
	FOUND_RATELIMIT_MAILFROM_REJECTS,
	FOUND_RATELIMIT_RCPTTO_REJECTS,
} found_what;

/*
 *	NAT header type
*/

typedef enum {
	NAT_HEADER_TYPE_NONE = 0,
	NAT_HEADER_TYPE_GENERIC,
	NAT_HEADER_TYPE_IP_ONLY
} nat_header_type_enum;

/*
 *	SMTP response struct
*/
struct response_code {
	int generic;		// 250
	int subject;		// 1
	int detail;		// 0
};


/*
 *	pipeline queue entry
*/
typedef void* pipeline_parm_t;

typedef union {
	int i;
	void *p;
	char *s;
} pipeline_arg_t;

static inline pipeline_arg_t arg_t_i(int i) { pipeline_arg_t a = {.i = i}; return a; };
static inline pipeline_arg_t arg_t_p(void *p) { pipeline_arg_t a = {.p = p}; return a; };
static inline pipeline_arg_t arg_t_s(char *s) { pipeline_arg_t a = {.s = s}; return a; };

struct pipeline_t {
	smtp_command_t cmd;
	pipeline_arg_t parm1;	/* BDAT bytes to go */
	pipeline_arg_t parm2;	/* BDAT LAST */
};

/*
 *	operational modes
*/

typedef enum {
	MODE_NONE = 0,
	// forward to fixed address:port
	// MUA/MTA => { smtp-gated } => ISP-MTA/MDA
	MODE_FIXED,
	// forward to fixed address:port, issuing XCLIENT with source address first
	// MUA/MTA => { smtp-gated(xclient) => (xclient)MTA } => ISP-MTA/MDA
	MODE_FIXED_XCLIENT,
	// forward to fixed address, but use sniffed XCLIENT address as source (i.e. for locking)
	// MUA/MTA => { MTA(xclient) => smtp-gated => (xclient)MTA } => ISP-MTA/MDA
	MODE_FIXED_XCLIENT_PROXY,
	// forward using XRELAY from=[192.168.1.1]:10582 dst=[212.180.255.1]:25 ident=192.168.1.1
	MODE_XRELAY,
	// forward using patched oidentd
	// MUA => { NAT(oidentd) => smtp-gated } => MSA
	MODE_REMOTE,
	// forward using proxy helper
	// MUA => { NAT(proxy-helper) => smtp-gated } => MSA
	MODE_REMOTE_UDP,
	// forward using getsockname()
	// MUA => NAT(getsockname + smtp-gated) => MSA
	MODE_GETSOCKNAME,
	// forward using netfilter getsockopt(SO_ORIGINAL_DST)
	// MUA => NAT(netfilter + smtp-gated) => MSA
	MODE_NETFILTER,
	// MODE_IPFW is an alias for MODE_GETSOCKNAME
	// MUA => NAT(ipfw + smtp-gated) => MSA
	MODE_IPFW,
	// forward using ioctl(IPFOBJ_NATLOOKUP/SIOCGNATL)
	// MUA => NAT(ipfilter + smtp-gated) => MSA
	MODE_IPFILTER,
	// forward using netfilter TPROXY extension
	// MUA => NAT(tproxy + smtp-gated) => MSA
	MODE_TPROXY,
	MODE_TPROXY_OR_NETFILTER,
	// forward using BSD ioctl(DIOCNATLOOK)
	// MUA => NAT(pf + smtp-gated) => MSA
	MODE_PF
} mode_enum;


/*
 *	session data
*/
struct session_t {
	mode_enum mode;

	// connections fd
	int client;			// (from) client socket
	int server;			// (to) server socket

	// connection data
	char ident[IDENT_SIZE+1];	// remote size ident string
//	char *client_filename;		// filename "ip-ident" 192.168.100.102-x8Fa8d67
	char *helo;			// HELO/EHLO string

	struct sockaddr_in origin;	// source (client/NAT) address+port
	char origin_str[16];		// source (client/NAT) IP text-address

	struct sockaddr_in target;	// target (SMTP server) address+port
	char target_str[16];		// target (SMTP server) IP text-address

	struct sockaddr_in local;	// source -> local address data
//	char local_str[16];		// local IP text-address

	// buffers
	char *cli_buf;			// bufor danych od klienta
	char *srv_buf;			// bufor danych z serwera
	int cli_size;			// ilosc danych w buforach
	int srv_size;

	int command_pos_client;		// queue position for client
	int command_pos_server;		// queue position for server
	int pipeline_size;		// session allocated pipeline size
	struct pipeline_t *pipeline;	// command pipeline queue

	// nat header, to be injected to message
	char *xheader;			// NAT X-Received header
	int xheader_size;		// NAT X-Received header length

	// spooling data
	size_t size;			// spool size
	size_t header_size;		// spool header size
	size_t extra_size;		// injected Spool-Info header size
	char *spool_name;		// spool file name
	int spool_fd;			// spool file descriptor || -1
	int spool_exists;		// spool file created && !deleted

	// lock file
	char *lockfile;			// lock filename
	int rate_fd;			// ratefile descriptor
#ifdef HAVE_MMAP
	int rate_mapsize;
	struct ratelimit_record_t *rate_map;	// mmap()ed ratefile
	struct ratelimit_md5_t *rate_helos;
	struct ratelimit_md5_t *rate_mails;
	struct ratelimit_ip_t *rate_dst;
#endif

	// extensions
	int enhancedstatuscodes;	// ENHANCEDSTATUSCODES
	int xclient;			// XCLIENT support
	int chunking;			// CHUNKING
	int auth;			// AUTH_FLAG_*

	// RFC 3030, BDAT n [LAST]
	// transaction_mode {NONE, DATA, BDAT}
	int data_used;			// DATA issued (per transaction)
	int bdat_used;			// BDAT issued (per transaction)
	int bdat_last;			// last chunk indicator [flag]
	int bdat_togo;			// bytes left to be read

	// DATA state
	data_phase data_going;		// DATA going

	// virus name
	char *virus_name;		// if found or NULL
	double spam_score;		// if spam found or SPAM_SCORE_NONE
	found_what found;		// what have we found in mail

	// recipients
	char *mail_from;		// pointer to mail from address
	int mail_from_logged;		// mail from was logged
	char *rcpt_to[RCPTS_ONE_TIME];	// pointers to mail recipients
	int rcpt_to_code[RCPTS_ONE_TIME];	// rcpt[i] is accept code by MTA
	int rcpts;			// recipients in buffer

	// statistics
	unsigned int cli_rx, srv_rx;	// statistics byte-counters
	unsigned int rcpts_total;	// recipients count for all transactions
	unsigned int transaction;	// SMTP transaction no.
	time_t start_time;		// start time

	// uzywana tylko przy USE_SHARED_MEM, ale jest w logach wiec zostaje
	unsigned int ident_count;	// count clients from this ident (not IP)

	// uzywane tylko przez wait_for_quit
	char *message;
	unsigned int command_count;
};


/*
 *	connection info (statistics)
*/
struct scoreboard_t {
	in_addr_t src;
	time_t start_time;

#ifdef USE_SHARED_MEM
	conn_state state;
	int auth;

	uint32_t dst;
	size_t cli_rx, srv_rx;
	size_t transaction;

	int ident_ok;
	char ident[IDENT_SIZE+1];
#endif
};


/*
 *	global statistics (shared)
*/
struct stat_info {
	time_t started;
	time_t restarted;

	unsigned int max_children;

	unsigned int child_crashes;
	time_t child_crash_last;

	unsigned int child_bugs;
	time_t child_bug_last;

	unsigned int requests;
	unsigned int requests_direct;
	unsigned int requests_empty;

	// connection rejections
	unsigned int rejects_other;
	unsigned int rejects_host;
	unsigned int rejects_lock;
	unsigned int rejects_dnsbl;	/* would be in protocol rejections for 'skip_auth dnsbl' */
	unsigned int rejects_ident;
	unsigned int rejects_rate;
	unsigned int rejects_ratelimit;

	// connection errors
	unsigned int errors_pipeline_full;
	unsigned int errors_ratelimit;

	// protocol rejections
	unsigned int viruses;
	unsigned int spams;
	unsigned int spf;			/* spf violations */
	unsigned int regex;			/* regex_* violations */
	unsigned int noauths;			/* auth_require violations */
	unsigned int earlytalk;			/* earlytalkers */

	/* software failures */
	unsigned int fail_antivirus;
	unsigned int fail_antispam;
	unsigned int fail_dnsbl;
	unsigned int fail_spf;
	unsigned int fail_regex;

	/* authentication stats */
	unsigned int auth_accepts;
	unsigned int auth_rejects;
};


/*
 *	universal slot cache for high max_connections
 *	slot_list_entry_t for free slots, and for busy slot hash

	free_slots -> slot -> slot -> slot -> NULL
	pid_hash
		-> slot -> slot
		-> slot
		-> slot -> slot -> slot -> slot
*/

/* for child_reaper */
struct slot_hash_entry_t {
	struct slot_hash_entry_t *next;
//	struct slot_hash_entry_t *next_ip;
	int slot;
	/* pid := pids[slot] */
};

// slot_hash_entry_t *free_slots;
// slot_hash_entry_t pid_hash_table[max_connections/8];


struct host_hash_entry_t {
	struct host_hash_entry_t *next;
	in_addr_t host;
	int count;
};

// TODO: maybe could be like for slot_has
// free_hash_slots and occupied_hash_slots
// there would be no need for malloc() and free()
// config.max_different_hosts



#define FORWARD_FLAG_NEED_ROOT		0x0001
#define FORWARD_HAS_IDENT			0x0002
#define FORWARD_SKIP_LOOP_CHECK		0x0004

struct forwarder_t {
	char *name;
	int mode;		// MODE_X
	int flags;
	/* initialize after ... */
	int (* init)();
	/* check config after ... */
	int (* config_check)();
	/* make a lookup */
	int (* lookup)(struct session_t *data);
	/* connect to target */
	int (* connect)(struct session_t *data);
	/* get config structure */
	void* (* get_config)();
};


typedef enum { VERB_RESULT_NONE = 0, VERB_RESULT_CONTINUE, VERB_RESULT_LAST, VERB_RESULT_STOLEN } verb_result_t;

struct verb_t {
	char *verb;
	int flags;	// exact, beginning_match
	smtp_command_t (*pre)(struct session_t *data, char *verb, int *param1, int *param2);
	smtp_command_t (*post)(struct session_t *data, char *verb, int code);
};


EXTERN struct option_enum facility_list[];
EXTERN struct option_enum priority_list[];



#ifndef _SMTP_GATED_C_
EXTERN volatile sig_atomic_t timedout;
EXTERN int i_am_a_child;
EXTERN struct stat_info *stats;
EXTERN struct scoreboard_t *connections;
EXTERN char *conn_states[];
EXTERN int max_connections_real;
EXTERN pid_t *pids;
EXTERN int children;
EXTERN int child_slot;
EXTERN struct option_enum nat_header_type_list[];
EXTERN struct option_enum mode_list[];
EXTERN struct option_enum log_mail_list[];
EXTERN struct option_enum auth_require_list[];
EXTERN struct option_enum auth_skip_list[];
#endif


EXTERN void helo(int client);
EXTERN void wait_for_quit(struct session_t *data, char* format, ...)
	__attribute__ ((noreturn, format (printf, 2, 3)));
EXTERN int response(struct session_t *data, struct response_code resp, char *format, ...)
	__attribute__ ((format (printf, 3, 4)));

#define BUG(format...)	bug(__FILE__, __FUNCTION__, __LINE__, format)
EXTERN void bug(const char *filename, const char *func, int lineno, const char *format, ...)
	__attribute__ ((format (printf, 4, 5)));


EXTERN void set_dump_state(conn_state s);
EXTERN void cleanup();
EXTERN char* compile_date();


#undef EXTERN

#endif
