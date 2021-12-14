/*
 * 	util.h
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


#ifndef _UTIL_H_
#define _UTIL_H_

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <netinet/in.h>
#include <errno.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif



#ifndef _UTIL_C_
#define EXTERN extern
#else
#define EXTERN
#endif


/*
 *	useful macros
*/

#define SIN_TO_UINT32(x)		(*((uint32_t *) &(x)))
#define UINT32_TO_SIN(x)		(*((struct in_addr *) &(x)))

#define EMPTY_STRING(x) 		(x == NULL || x[0] == '\0')
#define TERMINATE_STRING(s) 	{ s[sizeof(s)-1] = '\0'; }

#define FREE_NULL(x) 			{ if (x != NULL) { free(x); x = NULL; }; }
#define PTRADD(p, a)			((typeof(p)) (((char*) p) + (a)))


// 20101014
#define SAFE_CLOSE(x)	\
	{ if (x != -1) { while ((close(x) == -1) && (errno == EINTR)); x = -1; }; }


#define ASSERT(e)	\
	{ if (!(e)) log_action(LOG_DEBUG, "ASSERT failed on %s:%s:%d [%s]", __FILE__, __FUNCTION__, __LINE__, #e); }
#define assert(e)	ASSERT(e)

/*
	bit flags
*/
#define IS_FLAG_EQ(v, f)				(((v) & (f)) == (f))
#define IS_FLAG_SET(v, f)				(((v) & (f)) != 0)
#define IS_FLAG_CLEARED(v, f)			(((v) & (f)) == 0)
#define IS_FLAG_MASK_EQ(v, m, f)		(((v) & (m)) == (f))
#define IS_FLAG_MASK_NE(v, m, f)		(((v) & (m)) != (f))



#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIPQUAD_REV(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]


#define NIPQUAD_UINT(addr) \
	(addr >> 0) & 0xFF, \
	(addr >> 8) & 0xFF, \
	(addr >> 16) & 0xFF, \
	(addr >> 24) & 0xFF

// htonl() should be smart enough to act as __constant_htonl
#define IP4(a,b,c,d)			htonl((uint32_t) (a << 24) + (uint32_t) (b << 16) + (uint32_t) (c << 8) + d)
#define SUBNET(address, network, mask)	((address & mask) == (network & mask))

// struct sockaddr_in
#define SA_IPPORT(addr) \
	((unsigned char *)&addr.sin_addr.s_addr)[0], \
	((unsigned char *)&addr.sin_addr.s_addr)[1], \
	((unsigned char *)&addr.sin_addr.s_addr)[2], \
	((unsigned char *)&addr.sin_addr.s_addr)[3], \
	ntohs(addr.sin_port)


/*
 *	printf formats
*/

#if SIZEOF_PID_T == 8
#define FORMAT_PID_T "ld"
#else
#define FORMAT_PID_T "d"
#endif

#if SIZEOF_UID_T == 8
#define FORMAT_UID_T "ld"
#else
#define FORMAT_UID_T "d"
#endif

#if SIZEOF_TIME_T == 8
#define FORMAT_TIME_T "lu"
#else
#define FORMAT_TIME_T "lu"
#endif

#if SIZEOF_SIZE_T == 8
#define FORMAT_SIZE_T "lu"
#else
#define FORMAT_SIZE_T "lu"
#endif

#define ARRAY(t, x...)	(t[]) {x}
#define ARRAYSIZE(t)	(sizeof(t)/sizeof(t[0]))

// const
#define M	*1024*1024
#define K	*1024

/*
 *	log_action()
*/
#define LOG_ALWAYS			0x10
#define LOG_LIMIT			0x20
#define LOG_FORE_ONLY			0x40
#define LOG_TERMINAL			0x80


// "rozszerzenie" sysloga na potrzeby programu
// log_action() przycina priorytet komunikatow do
// LOG_DEBUG jesli sa wyzsze
#define LOG_VERBOSE			0x08

// setup_socket flags
//#define SOCKET_LISTEN		0x0001

/*
 *	logging setup
*/

//EXTERN struct option_enum facility_list[];
//EXTERN struct option_enum priority_list[];

/*
 *	Connection status returned by fdgetline_cb() callbacks
*/

typedef enum {
	LINE_OK = 0, LINE_CLOSED, LINE_BINARY,				// ---- fdgetline_cb callback
	LINE_EINTR,							// ---- fdgetline_cb -------- EINTR=timeout
	LINE_CLOSED_SERVER, LINE_CLOSED_TIMEOUT, LINE_CLOSED_ADMIN,	// loop ------------ --------
	LINE_ERROR
} line_status;


typedef line_status (* line_callback)(char* buf, char* pos, int size, void *ptr);


/*
 *	snprintp
 *
 *	format padding, prepend using space if parameter is not empty:
 *	'%a%_a %a' => 'a a a'
 *	'%a%b %a' => 'a a'
*/

#define SNPRINTP_FORMAT_PAD		'_'
#define SNPRINTP_FORMAT_CHAR	'%'
#define SNPRINTP_PARAMS(x...)	(snprintp_paramt[]) (x)
#define LOG_FUNC_ERR(x)			log_action(LOG_ERR, "%s.%s: %s", __FUNCTION__, x, strerror(errno));


typedef enum {
   	SNPRINTP_NONE = 0,
	SNPRINTP_CHAR,
	SNPRINTP_INT, SNPRINTP_UINT,
   	SNPRINTP_DOUBLE,
   	SNPRINTP_BOOLEAN,
   	SNPRINTP_PTR,
	SNPRINTP_STRING,
	SNPRINTP_STRING_SQL,
	SNPRINTP_INET, SNPRINTP_INET6
} psnprint_type_t;

struct snprintp_param_t {
	char token;
	psnprint_type_t type;
	int flags;
	union {
		char c;
		double d;
		int i;
		unsigned int u;
		char *s;
		void *ptr;
		in_addr_t inet;
//		in6_addr in6;
	} u;
};

#if 0
struct snprintp_param_t {
	char token;
	char *format;
	void *data;
};
#endif



/*
 *	zmienne
*/

#ifndef _UTIL_C_
EXTERN int log_level;
EXTERN int foreground;
#endif

/*
 *	funkcje
*/

#ifdef USE_NAT_TPROXY
EXTERN int tproxy_check();
#if 0
EXTERN int connect_host_tproxy(struct sockaddr_in dst, int dst_port,
	struct sockaddr_in src, struct sockaddr_in tproxy_src);
#endif
#endif

EXTERN int connect_path(char *path);
EXTERN int connect_host(struct sockaddr_in dst, int dst_port, struct sockaddr_in src, int socket_options[], int ip_options[]);
EXTERN int connect_host_from_port(struct sockaddr_in dst, int dst_port, struct sockaddr_in src, int socket_options[], int ip_options[]);
EXTERN int setup_socket_in(int proto, in_addr_t ip, int port, int backlog, int socket_options[], int ip_options[]);
EXTERN int setup_socket(int proto, char *addr, int port, int backlog, int socket_options[], int ip_options[]);
EXTERN ssize_t safe_write(int fd, const void *buf, size_t count);

EXTERN void die(int code, char *format, ...)
	__attribute__ ((format (printf, 2, 3)))
	__attribute__ ((noreturn));
EXTERN void log_action(int prio, char* format, ...)
	__attribute__ ((format (printf, 2, 3)));
EXTERN int fdprintf(int fd, char* format, ...)
	__attribute__ ((format (printf, 2, 3)));
EXTERN int openf(int flags, const char* format, ...)
	__attribute__ ((format (printf, 2, 3)));

EXTERN char* fdgetline(int fd, char* buf, size_t sizeof_buf, int *buf_size, int *offset);
EXTERN line_status fdgetline_cb(int fd, char* buf, size_t sizeof_buf, int *buf_size,
	line_callback callback, void *ptr, unsigned int *rx_bytes);

EXTERN void untaint(/*@null@*/char *str, size_t len);
EXTERN void untaint_for_filename(/*@null@*/char *str, size_t len);
EXTERN int is_load_above(double max, double *current);

EXTERN char* time2str(time_t t);
EXTERN void time2dhms(int t, int *d, int *h, int *m, int *s);

EXTERN char* line_closed_cause(line_status st);

EXTERN char* alloc_msg_mail(char *line, int len)
	__attribute__ ((malloc));
EXTERN char* alloc_str_crlf(char *line, int len)
	__attribute__ ((malloc));

#ifdef USE_SHARED_MEM
EXTERN void* shmalloc(size_t size, int *id)
	__attribute__ ((malloc));
EXTERN int shmfreeid(int id);
#endif

#ifdef HAVE_IP_PKTINFO
EXTERN struct in_pktinfo* get_pktinfo(struct msghdr *msg);
#endif

EXTERN int cat(char *fn);
EXTERN int setup_signals(void (*handler)(int signum), int handle_signals[], int ignore_signals[]);
#ifdef HAVE_SETRLIMIT
EXTERN int set_rlimit(int what, rlim_t value);
#endif

EXTERN u_int32_t netmask(int m);
EXTERN int parse_ip_mask(char* str, u_int32_t* ip, u_int32_t* mask);
EXTERN int is_routable(in_addr_t addr);

EXTERN int snprintp(char *buf, size_t buf_len, const char *format, struct snprintp_param_t params[]);

/*@unused@*/ static inline int min(int a, int b) { return (a < b) ? a : b; }
/*@unused@*/ static inline int min3(int a, int b, int c) { return (a < b) ? min(a, c) : min(b, c); }
/*@unused@*/ static inline int max(int a, int b) { return (a > b) ? a : b; }
/*@unused@*/ static inline int max3(int a, int b, int c) { return (a > b) ? max(a, c) : max(b, c); }
/*@unused@*/ static inline int between(int x, int a, int b) { return ((x >= a) && (x <= b)); }


#undef EXTERN
#endif

