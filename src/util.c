/*
 * 	util.c
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
#define _UTIL_C_


#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#ifdef HAVE_SYS_LOADAVG_H
#include <sys/loadavg.h>
#endif

#ifdef USE_SHARED_MEM
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

#ifdef USE_NAT_TPROXY
#include <sys/types.h>
#include <asm/byteorder.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter/xt_TPROXY.h>
#endif

//#include "confvars.h"
//#include "daemon.h"
#include "util.h"
//#include "smtp-gated.h"


/*
 *	configuration
*/

int log_level = LOG_DEBUG;
int foreground = 0;

/*
 * 	constants
*/

#ifndef PRINTF_SIZE
#define PRINTF_SIZE 1024
#endif

static const int one = 1;

#if 0
struct option_enum facility_list[] = {
//	{ "kern", LOG_KERN },
	{ "user", LOG_USER },
	{ "mail", LOG_MAIL },
	{ "daemon", LOG_DAEMON },
	{ "auth", LOG_AUTH },
//	{ "lpr", LOG_LPR },
	{ "news", LOG_NEWS },
//	{ "uucp", LOG_UUCP },
#ifdef LOG_AUDIT
	{ "audit", LOG_AUDIT },
#endif
//	{ "cron", LOG_CRON },
#ifdef LOG_AUTHPRIV
	{ "authpriv", LOG_AUTHPRIV },
#endif
#ifdef LOG_FTP
//	{ "ftp", LOG_FTP },
#endif
	{ "local0", LOG_LOCAL0 },
	{ "local1", LOG_LOCAL1 },
	{ "local2", LOG_LOCAL2 },
	{ "local3", LOG_LOCAL3 },
	{ "local4", LOG_LOCAL4 },
	{ "local5", LOG_LOCAL5 },
	{ "local6", LOG_LOCAL6 },
	{ "local7", LOG_LOCAL7 },
	{ NULL }
};

struct option_enum priority_list[] = {
	{ "alert", LOG_ALERT },
	{ "crit", LOG_CRIT },
	{ "debug", LOG_DEBUG },
	{ "emerg", LOG_EMERG },
	{ "err", LOG_ERR },
	{ "info", LOG_INFO },
	{ "notice", LOG_NOTICE },
	{ "warning", LOG_WARNING },
	{ NULL }
};

#endif

/*
 *	TPROXY
*/

#ifdef USE_NAT_TPROXY
int tproxy_check()
{
#if 0
	struct in_tproxy itp;
	int sock;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) return -1;

	itp.op = TPROXY_VERSION;
	itp.v.version = 0x04000000;
	if (setsockopt(sock, IPPROTO_IP, IP_TPROXY, &itp, sizeof(itp)) == -1) {
		SAFE_CLOSE(sock);
		return -1;
	}

	SAFE_CLOSE(sock);
#endif
	return 0;
} /* tproxy_check() */

#if 0
int connect_host_tproxy(struct sockaddr_in dst, int dst_port,
	struct sockaddr_in src, struct sockaddr_in tproxy_src)
{
	struct in_tproxy itp;
	int res;
	int sock;


	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) return -1;

	// konieczne?!
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		goto fail;

	src.sin_family = AF_INET;
	src.sin_port = 0;
	if (bind(sock, (struct sockaddr *) &src, sizeof(src)) == -1)
		goto fail;

	itp.op = TPROXY_ASSIGN;
	itp.v.addr.faddr = tproxy_src.sin_addr;
	itp.v.addr.fport = tproxy_src.sin_port;
	if (setsockopt(sock, IPPROTO_IP, IP_TPROXY, &itp, sizeof(itp)) == -1)
		goto fail;

	itp.op = TPROXY_FLAGS;
	itp.v.flags = ITP_CONNECT;
	if (setsockopt(sock, IPPROTO_IP, IP_TPROXY, &itp, sizeof(itp)) == -1)
		goto fail;

	dst.sin_family = AF_INET;
	dst.sin_port = htons(dst_port);
	if (connect(sock, (struct sockaddr *) &dst, sizeof(dst)) == -1)
		goto fail;

	return sock;

fail:
	res = errno;
	if (sock != -1) SAFE_CLOSE(sock);
	return -1;
} /* connect_host_tproxy() */
#endif
#endif

/*
 *	connect host
*/

/*
 * alarm(...)
 * connect_host()
 * alarm(0);
*/

int connect_host_from_port(struct sockaddr_in dst, int dst_port, struct sockaddr_in src, int socket_options[], int ip_options[])
{
	int res;
	int fd;


	if ((fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return -1;

	if (socket_options) {
		for (; *socket_options; socket_options++) {
			if (setsockopt(fd, SOL_SOCKET, *socket_options, &one, sizeof(one)) == -1) {
				log_action(LOG_CRIT, "setsockopt(%d): %s", *socket_options, strerror(errno));
				goto fail;
			}
		}
	}
	if (ip_options) {
		for (; *ip_options; ip_options++) {
			if (setsockopt(fd, IPPROTO_IP, *ip_options, &one, sizeof(one)) == -1) {
				log_action(LOG_CRIT, "setsockopt(%d): %s", *ip_options, strerror(errno));
				goto fail;
			}
		}
	}

	if (bind(fd, (struct sockaddr *) &src, sizeof(src)) == -1)
		goto fail;

	dst.sin_family = AF_INET;
	dst.sin_port = htons(dst_port);

	if (connect(fd, (struct sockaddr *) &dst, sizeof(dst)) == -1)
		goto fail;

	return fd;

fail:
	res = errno;
	if (fd != -1) SAFE_CLOSE(fd);
	errno = res;
	return -1;
}

int connect_host(struct sockaddr_in dst, int dst_port, struct sockaddr_in src, int socket_options[], int ip_options[])
{
	src.sin_family = AF_INET;
	src.sin_port = 0;
	return connect_host_from_port(dst, dst_port, src, socket_options, ip_options);
} /* connect_host() */

int connect_path(char *path)
{
	int sock;
	int port, save;
	char *port_pos;
	struct sockaddr_un us;
	struct sockaddr_in sin;

	if (!path) {
		errno = EINVAL;
		return -1;
	}

	sock = -1;

	if (path[0] == '/') {
		if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
			goto fail;
		}

		us.sun_family = AF_UNIX;
		strncpy(us.sun_path, path, sizeof(us.sun_path));
		TERMINATE_STRING(us.sun_path);

		if (connect(sock, (struct sockaddr*) &us, sizeof(us)) == -1) {
			goto fail;
		}
	} else {
		port_pos = strchr(path, ':');
		if (port_pos == NULL) {
			errno = EINVAL;
			goto fail;
		}

		*port_pos = '\0';
		if (inet_aton(path, &sin.sin_addr) == 0) {
			*port_pos = ':';
			errno = EINVAL;
			goto fail;
		}

		*port_pos = ':';
		port = atoi(port_pos+1);

		if (port < 1 || port > 65535) {
			errno = ERANGE;
			goto fail;
		}

		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);

		if ((sock = socket(PF_INET, SOCK_STREAM, getprotobyname("tcp")->p_proto)) == -1) {
			goto fail;
		}

		if (connect(sock, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
			goto fail;
		}
	}

	// errno = ENXIO;
	return sock;

fail:
	save = errno;
	if (sock != -1) SAFE_CLOSE(sock);
	errno = save;
	return -1;
} /* connect_path() */


/*
 * 	setup listening socket
*/


int setup_socket_in(int proto, in_addr_t ip, int port, int backlog, int socket_options[], int ip_options[])
{
	struct sockaddr_in addr;
	int fd;


	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		log_action(LOG_CRIT, "setup_socket_in(): invalid protocol %d", proto);
		errno = EINVAL;
		return -1;
	}

	if ((fd = socket(PF_INET, (proto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM, proto)) == -1) {
		log_action(LOG_CRIT, "socket(): %s", strerror(errno));
		return -1;
	}

	if (socket_options) {
		for (; *socket_options; socket_options++) {
			if (setsockopt(fd, SOL_SOCKET, *socket_options, &one, sizeof(one)) == -1) {
				log_action(LOG_CRIT, "setsockopt(%d): %s", *socket_options, strerror(errno));
				SAFE_CLOSE(fd);
				return -1;
			}
		}
	}
	if (ip_options) {
		for (; *ip_options; ip_options++) {
			if (setsockopt(fd, IPPROTO_IP, *ip_options, &one, sizeof(one)) == -1) {
				log_action(LOG_CRIT, "setsockopt(%d): %s", *ip_options, strerror(errno));
				SAFE_CLOSE(fd);
				return -1;
			}
		}
	}

	if (ip || port) {
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = ip;

		if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
			log_action(LOG_CRIT, "bind(): %s", strerror(errno));
			SAFE_CLOSE(fd);
			return -1;
		}
	}

	if (backlog != -1) {
		if (listen(fd, backlog) == -1) {
			log_action(LOG_CRIT, "listen(): %s", strerror(errno));
			SAFE_CLOSE(fd);
			return -1;
		}
	}

	return fd;
} /* setup_socket_in() */


int setup_socket(int proto, char *addr, int port, int backlog, int socket_options[], int ip_options[])
{
	struct in_addr ip;

	if (inet_aton(addr, &ip) == 0) {
		log_action(LOG_CRIT, "inet_aton(): %s", strerror(errno));
		errno = EINVAL;
		return -1;
	}

	return setup_socket_in(proto, ip.s_addr, port, backlog, socket_options, ip_options);
} /* setup_socket() */


#ifdef HAVE_IP_PKTINFO
/* parse msghdr from recvmsg */
struct in_pktinfo* get_pktinfo(struct msghdr *msg)
{
        struct cmsghdr *cmsg;

        for (cmsg = CMSG_FIRSTHDR(msg); cmsg!=NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
                if (cmsg->cmsg_level != IPPROTO_IP)
                        continue;
                if (cmsg->cmsg_type != IP_PKTINFO)
                        continue;

                // UDP destination IP: ipi_addr == 255.255.255.255
                // UDP real/local IP: ipi_spec_dst == 192.168.99.254
                return (struct in_pktinfo *) CMSG_DATA(cmsg);
        }

        return NULL;
}
#endif

/*
 * 	get line from fd
 * 	replaces '\r' and '\n' with '\0'
 * 	sets errno and returns NULL on error
*/

char* fdgetline(int fd, char* buf, size_t sizeof_buf, int *buf_size, int *offset)
{
	ssize_t size;
	char *nl;

	if (*offset) {
		memmove(buf, buf+*offset, *buf_size-*offset);
		(*buf_size) -= *offset;
	}

	for (;;) {
		nl = memchr(buf, '\n', *buf_size);
		if (nl) {
			nl[0] = '\0';
			if (nl > buf && nl[-1] == '\r') nl[-1] = '\0';

			if (buf + *buf_size <= nl) {
				*buf_size = 0;
				*offset = 0;
			} else {
				*offset = nl - buf + 1;	// skip newline
			}
			return buf;
		}

		if (*buf_size >= sizeof_buf) { // argh! never ending line!
			errno = ENOMEM;
			return NULL;
		}

		if ((size = read(fd, buf + (*buf_size), sizeof_buf - (*buf_size))) == -1) {
			if (errno == ECONNRESET) return NULL;
			if (errno == EINTR || errno == ETIMEDOUT) return NULL;
			log_action(LOG_ERR, "fdgetline:read error: %s", strerror(errno));
			return NULL;
		}

		if (size == 0) {
			errno = 0;
			return NULL;
		}
		(*buf_size) += size;
	}
} /* fdgetline() */

// callback moze zwrocic: LINE_OK, LINE_CLOSED, LINE_BINARY
line_status fdgetline_cb(int fd, char* buf, size_t sizeof_buf, int *buf_size, line_callback callback, void *ptr, unsigned int *rx_bytes)
{
	int size;
	char *current, *nl;
	line_status res = LINE_OK;

	if ((size = read(fd, buf + (*buf_size), sizeof_buf - (*buf_size))) == -1) {
#ifdef SILENT_ECONNRESET
		if (errno == ECONNRESET) return LINE_CLOSED;
#endif
		if (errno == EINTR || errno == ETIMEDOUT) return LINE_EINTR;
		log_action(LOG_ERR, "fdgetline_cb:read error: %s", strerror(errno));
		return LINE_CLOSED;
	}
	if (size == 0) return LINE_CLOSED;

	if (rx_bytes) (*rx_bytes) += size;
	(*buf_size) += size;

	for (current = buf;;) {
		nl = memchr(current, '\n', *buf_size);
		if (nl == NULL) {
			// dluga linia bez zakonczenia (ani CRLF ani \0)
			// stara sie najpierw skompletowac caly bufor
			// wlasciwie to drugi warunek zawiera pierwszy
			if (current == buf && *buf_size == sizeof_buf) {
				res = callback(current, NULL, *buf_size, ptr);
				*buf_size = 0;
			}
			break;
		} else {
			// nl na koncu linii: [nl] == '\n'
			size = nl - current + 1;
			res = callback(current, nl, size, ptr);
			*buf_size -= size;

			// jesli res != LINE_OK to cos sie dzieje
			// albo blad, albo LINE_BINARY
			if (res != LINE_OK || *buf_size == 0) break;
			current += size;
		}
	}

	// przesun dane na poczatek bufora
	if (*buf_size) memmove(buf, current, *buf_size);
	return res;
} /* fdgetline_cb() */



/*
 *	file descriptor printf()
*/

int fdprintf(int fd, char* format, ...)
{
	va_list ap;
	char buf[PRINTF_SIZE];
	int size, res, pos;

	va_start(ap, format);
	size = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);

	if (size == -1 || size > sizeof(buf)) {
		errno = ENOMEM;
		return -1;
	}

	for (pos = 0;;) {
/*
		if (timedout) {
			errno = ETIMEDOUT;
			return -1;
		}
*/
		if ((res = write(fd, buf+pos, size-pos)) == -1) {
			if (errno == EINTR) continue;
//			if (errno == ECONNRESET) return -1;
			return -1;
		}

		if (res == 0) break;

		pos += res;
		if (pos == size) break;
	}

	return res;
} /* fdprintf() */


/*
 * write, restarting on EINTR if necessary
 * may cause desync on some errno-s
*/

ssize_t safe_write(int fd, const void *buf, size_t count)
{
	int res;
	do {
		if ((res = write(fd, buf, count)) == -1 && errno == EINTR)
			continue;
		if (res == -1)
			break;
		buf += res;
		count -= res;
	} while (count > 0);
	return res;
} /* safe_write() */


/*
 * 	(sys)logging
*/

void die(int code, char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(code);
}

// does not break errno (!!), really necessary?
void log_action(int prio, char* format, ...)
{
	va_list ap;
	char buf[1024];
	int save = errno;


	if (IS_FLAG_SET(prio, LOG_FORE_ONLY)) {
		if (!foreground)
			return;
		prio &= ~(int) LOG_FORE_ONLY;
	}

	if (IS_FLAG_SET(prio, LOG_ALWAYS)) {
		prio &= ~(int) LOG_ALWAYS;
	} else {
		if (prio > log_level) return;
	}

	if (foreground || IS_FLAG_SET(prio, LOG_TERMINAL)) {
		// does fprintf return -1 and set errno?
		fprintf(stderr, "[%d] ", getpid());

		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);

		fprintf(stderr, "\n");
	} else {
		va_start(ap, format);
		vsnprintf(buf, sizeof(buf), format, ap);
		va_end(ap);
		TERMINATE_STRING(buf);

		if (prio > LOG_DEBUG) prio = LOG_DEBUG;
		syslog(prio, buf);
	}
	errno = save;
} /* log_action() */


/*
 * 	shared memory
*/

#ifdef USE_SHARED_MEM
void* shmalloc(size_t size, int *id)
{
	void *ptr;
	int save;

	*id = shmget(IPC_PRIVATE, size, IPC_CREAT | 0600);
	if (*id == -1) {
		log_action(LOG_CRIT, "shmget(%d) failed: %s", size, strerror(errno));
		return NULL;
	}

	ptr = shmat(*id, NULL, 0);
	if (ptr == (void *) -1) {
		save = errno;
		log_action(LOG_CRIT, "shmat() failed: %s", strerror(errno));
		shmctl(*id, IPC_RMID, NULL);
	   	*id = -1;
		errno = save;
		return NULL;
	}

/*
	if (shmctl(*id, IPC_RMID, NULL) == -1) {
		log_action(LOG_CRIT, "shmctl(IPC_RMID) failed: %s", strerror(errno));
		return NULL;
	}
*/

	return ptr;
} /* shmalloc() */

int shmfreeid(int id)
{
	if (id == -1) return 0;

	if (shmctl(id, IPC_RMID, NULL) == 0) return 0;

	log_action(LOG_ERR, "shmctl(IPC_RMID) failed: %s", strerror(errno));
	return -1;
} /* shmfreeid() */
#endif


/*
 * 	removing unwanted characters from strings
*/

void untaint(/*@null@*/ char *str, size_t len)
{
	if (str == NULL) return;

	if (len > 0) str[len-1] = '\0';

	for (; *str; str++) {
//		if (*str < 32 || *str > 127) *str = '#';
		if (*str < 32) *str = '#';
	}
} /* untaint() */

void untaint_for_filename(/*@null@*/ char *str, size_t len)
{
	if (str == NULL) return;

	if (len > 0) str[len-1] = '\0';

	for (; *str; str++) {
		if (*str >= 'A' && *str <= 'Z') continue;
		if (*str >= 'a' && *str <= 'z') continue;
		if (*str >= '0' && *str <= '9') continue;
		switch (*str) {
			case '-':
			case '=':
			case '+':
			case ':':
				continue;

			default:
				*str = '_';
		}
	}
} /* untaint_for_filename() */


/*
 * 	other functions
*/

int is_load_above(double max, /*@null@*/ double *current)
{
	int res;
	double load[2];

	load[0] = load[1] = 0.0;
	if ((res = getloadavg(load, 2)) < 1) {
		log_action(LOG_ERR, "getloadavg() failed (%d)", res);
		if (current != NULL) *current = -1;
		return -1;
	}

	if (current != NULL) *current = load[0];
	if (max <= 0) return 0;

	if (load[0] > max) return 1;
	return 0;
} /* is_load_above() */

char* time2str(time_t t)
{
	static char buf[128];
	char c[] = "%c";	// jako zmienna, bo inaczej kompilator sie pluje

	// glibc warning
	strftime(buf, sizeof(buf), c, localtime(&t));
	TERMINATE_STRING(buf);

	return buf;
} /* time2str() */

void time2dhms(int t, int *d, int *h, int *m, int *s)
{
	*d = t / (3600*24);
	t %= (3600*24);
	*h = t / 3600;
	t %= 3600;
	*m = t / 60;
	t %= 60;

	*s = t;
} /* time2dhms */


char* line_closed_cause(line_status sta)
{
	switch (sta) {
		case LINE_OK:
			return "ok";
		case LINE_BINARY:
			return "binary";
		case LINE_EINTR:
			return "eintr";
		case LINE_CLOSED:
			return "client";
		case LINE_CLOSED_SERVER:
			return "server";
		case LINE_CLOSED_TIMEOUT:
			return "timeout";
		case LINE_CLOSED_ADMIN:
			return "admin";
		case LINE_ERROR:
			return "error";
	}

	return "unknown-bug";
} /* line_closed_cause */

// MAIL FROM: bartek@isp.pl
// MAIL FROM: <bartek@isp.pl>
// MAIL FROM:<bartek@isp.pl   > BODY=8BIT
char* alloc_msg_mail(char *line, int len)
{
	char buf[len+1];
	register unsigned char c;
	int i;

	if (!line) return NULL;

	// pomin spacje i tabulatory i '<' na poczatku
	while ((line[0] == ' ') || (line[0] == '\t') || (line[0] == '<')) line++;

	for (i=0; i<sizeof(buf); i++) {
		c = line[i];

		switch (c) {
		case '>':
		case ' ':
		case '\0':
		case '\t':
			buf[i] = '\0';
			goto quit;
		default:
			/* do not untaint here, just copy */
			buf[i] = c;
		}
	}

quit:
	TERMINATE_STRING(buf);

	return strdup(buf);
} /* alloc_msg_mail() */


char* alloc_str_crlf(char *line, int len)
{
	char buf[len+1];
	register unsigned char c;
	int i;

	if (!line) return NULL;

	for (i=0; i<sizeof(buf); i++) {
		c = line[i];

		switch (c) {
		case '\r':
		case '\n':
			buf[i] = '#';
			break;
		case '\0':
			buf[i] = '\0';
			goto quit;
		default:
			/* do not untaint here, just copy */
			buf[i] = c;
		}
	}

quit:
	TERMINATE_STRING(buf);
	return strdup(buf);
} /* alloc_str_crlf */


int cat(char *fn)
{
	char buf[4096];
	int size, res, pos, fd;

	if ((fd = open(fn, O_RDONLY)) == -1) {
		fprintf(stderr, "open(%s) error: %s\n", fn, strerror(errno));
		return -1;
	}

	for (;;) {
		if ((size = read(fd, buf, sizeof(buf))) == -1) {
			if (errno == EINTR) continue;

			fprintf(stderr, "read() error: %s\n", strerror(errno));
			SAFE_CLOSE(fd);
			return -1;
		}

		if (size == 0) break;

		for (pos=0; size>0; size-=res, pos+=res) {
			if ((res = fwrite(buf+pos, 1, size, stdout)) == -1) {
				if (errno == EINTR) continue;

				fprintf(stderr, "cat:write() error: %s\n", strerror(errno));
				SAFE_CLOSE(fd);
				return -1;
			}
		}
	}

	SAFE_CLOSE(fd);
	return 0;
} /* cat() */


int setup_signals(void (*handler)(int signum), int handle_signals[], int ignore_signals[])
{
	struct sigaction sa;

	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (handle_signals) {
		sa.sa_handler = handler;
		while (*handle_signals) {
			if (sigaction(*handle_signals, &sa, NULL) == -1)
				return -1;
			handle_signals++;
		}
	}

	if (ignore_signals) {
		sa.sa_handler = SIG_IGN;
		while (*ignore_signals) {
			if (sigaction(*ignore_signals, &sa, NULL) == -1)
				return -1;
			ignore_signals++;
		}
	}

	return 0;
} /* setup_signals() */


#ifdef HAVE_SETRLIMIT
int set_rlimit(int what, rlim_t value)
{
	struct rlimit lim;

	if (getrlimit(what, &lim) == -1) {
		log_action(LOG_WARNING, "getrlimit(%d): %s", what, strerror(errno));
		return -1;
	} else {
		lim.rlim_cur = value;
		if (setrlimit(what, &lim) == -1) {
			log_action(LOG_WARNING, "setrlimit(%d, cur:%ld, max:%ld), %s", what, lim.rlim_cur, lim.rlim_max, strerror(errno));
			return -1;
		}
	}
	return 0;
} /* set_rlimit() */
#endif

/* netmask(28) => 255.255.255.240 (network order) */
u_int32_t netmask(int m)
{
	inline u_int32_t power(u_int32_t x, u_int32_t y)
	{
		u_int32_t r = 1;
		while (y--) r*=x;
		return r;
	}

	if (m < 0)
		m = 0;

	if (m > 32)
		m = 32;

	return m ? htonl(0xffffffff - power(2, 32-m) + 1) : 0x00;
} /* netmask() */

int parse_ip_mask(char* str, u_int32_t* ip, u_int32_t* mask)
{
	unsigned int a, b, c, d, m = 32;
	int res;

	if ((res = sscanf(str, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &m)) < 4)
		return -1;

	if (a > 255 || b > 255 || c > 255 || d > 255 || m > 32)
		return -1;

	if (ip)
		*ip = htonl(a << 24 | b << 16 | c << 8 | d);

	if (mask)
		*mask = netmask(res == 5 ? m : 32);

	return 0;
} /* parse_ip_mask() */


int is_routable(in_addr_t addr)
{
	return !SUBNET(addr, IP4(192,168,0,0), IP4(255,255,0,0))
		&& !SUBNET(addr, IP4(172,16,0,0), IP4(255,240,0,0))
		&& !SUBNET(addr, IP4(10,0,0,0), IP4(255,0,0,0))
		&& !SUBNET(addr, IP4(169,254,0,0), IP4(255,255,0,0));
}


#warning openf(): TODO?
int openf(int flags, const char *format, ...)
{
	va_list ap;
	char *fn = NULL;

	va_start(ap, format);
	int ret = vasprintf(&fn, format, ap);
	va_end(ap);

	if (ret == -1 || fn == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ret = open(fn, flags);
	int save = errno;
	free(fn);
	errno = save;

	return ret;
} /* openf() */

int snprintp(char *buf, size_t buf_len, const char *format, struct snprintp_param_t params[])
{
	char tmp[8192], *cat_ptr, *buf_cur;
	const char *fmt_cur, *fmt_next;
	int fmt_len, cat_len;
	int space_prepend;
	struct snprintp_param_t *p;


	if (buf_len <= 0) return -ENOMEM;

	buf_cur = buf;
	buf_len = buf_len;		// looks nice
	fmt_next = format;
	fmt_len = strlen(format);

	for (;;) {
		fmt_cur = fmt_next;
//		printf("searching through [%s]\n", fmt_cur);
		fmt_next = strchr(fmt_cur, SNPRINTP_FORMAT_CHAR);
//		printf("fmt_pos: %d, next: %d\n", fmt_cur - format, fmt_next - format);

		// no further '%'
		if (!fmt_next) {
//			printf("format end; fmt_len: %d, buf_len: %d\n", fmt_len, buf_len);
			if (fmt_len >= buf_len) return -ENOMEM;
			memcpy(buf_cur, fmt_cur, fmt_len);
			buf_cur += fmt_len;
			break;
		}

		// copy the skipped part of the string
		memcpy(buf_cur, fmt_cur, (fmt_next - fmt_cur));
		buf_cur += (fmt_next - fmt_cur);

		// skip SNPRINTP_FORMAT_CHAR
		fmt_next++;
		fmt_len--;

		// invalid single SNPRINTP_FORMAT_CHAR
		if (*fmt_next == '\0') return -EINVAL;

		// escape SNPRINTP_FORMAT_CHAR
		if (*fmt_next == SNPRINTP_FORMAT_CHAR) {
			if (buf_len < 1) return -ENOMEM;
			*buf_cur = SNPRINTP_FORMAT_CHAR;
			buf_cur++;
			buf_len--;
			fmt_next++;
			fmt_len--;
			continue;
		} else if (*fmt_next == SNPRINTP_FORMAT_PAD) {
			fmt_next++;
			fmt_len--;
			space_prepend = 1;
		} else {
			space_prepend = 0;
		}

		// find token
		for (p = params; p->token != '\0'; p++) {
			if (*fmt_next == p->token) break;
		}

		// skip token char (token 'name')
		fmt_next++;
		fmt_len--;

		// token not found
		if (p->token == '\0') continue;

		switch (p->type) {
			case SNPRINTP_CHAR:
				cat_len = 1;
				cat_ptr = &(p->u.c);
				break;
			case SNPRINTP_STRING:
				cat_ptr = p->u.s;
				cat_len = strlen(cat_ptr);
				break;
			case SNPRINTP_STRING_SQL:
				cat_ptr = strncpy(tmp, p->u.s, sizeof(tmp));
				TERMINATE_STRING(tmp);
				for (; *cat_ptr != '\0'; cat_ptr++) {
					if ((*cat_ptr < 32) || (*cat_ptr == '\\') || (*cat_ptr == '\''))
						*cat_ptr = '_';
				}
				cat_ptr = tmp;
				cat_len = strlen(cat_ptr);
				break;
			case SNPRINTP_INT:
				cat_ptr = tmp;
				cat_len = snprintf(tmp, sizeof(tmp), "%d", p->u.i);
				break;
			case SNPRINTP_UINT:
				cat_ptr = tmp;
				cat_len = snprintf(tmp, sizeof(tmp), "%u", p->u.u);
				break;
			case SNPRINTP_DOUBLE:
				cat_ptr = tmp;
				cat_len = snprintf(tmp, sizeof(tmp), "%f", p->u.d);
				break;
			case SNPRINTP_BOOLEAN:
				cat_ptr = (p->u.i) ? "true" : "false";
				cat_len = strlen(cat_ptr);
				break;
			case SNPRINTP_PTR:
				cat_ptr = tmp;
				cat_len = snprintf(tmp, sizeof(tmp), "%p", p->u.ptr);
				break;
			case SNPRINTP_INET:
				cat_ptr = strncpy(tmp, inet_ntoa(*(struct in_addr *) p->u.inet), sizeof(tmp));
				cat_len = strlen(tmp);
				break;
			default:
				return -EINVAL;
		}

		space_prepend &= (cat_len != 0);
		if (space_prepend) {
			if (buf_len < 1) return -ENOMEM;
			*buf_cur = ' ';
			buf_cur++;
			buf_len--;
			fmt_next++;
			fmt_len--;
		}

		if (buf_len < cat_len) return -ENOMEM;

//		if (fmt_len >= buf_len + cat_len) return -ENOMEM;
		if (cat_len > buf_len) return -ENOMEM;
		if (cat_ptr) memcpy(buf_cur, cat_ptr, cat_len);
		buf_cur += cat_len;
		buf_len -= cat_len;
	}

	// no space for terminating-null?
	if (buf_len < 1) return -ENOMEM;
	*buf_cur = '\0';

	return (buf_cur - buf);
} /* snprintfp() */

#if 0
int main()
{
	char buf[128], *format;
	int ret;
	struct snprintp_param_t params[] = {
		{ 'a', SNPRINTP_CHAR, 0, { .c = 'Z' } },
		{ 'b', SNPRINTP_STRING, 0, { .s = "123" } },
		{ 'c', SNPRINTP_INT, 0, { .i = 789 } },
		{ 0 }
	};

	memset(buf, '%', sizeof(buf));
	buf[sizeof(buf)-1] = '\0';

	format = "abc%b%%%c%a%babc";
	printf("format: [%s]\n", format);

	ret = snprintp(buf, sizeof(buf), format, params);
	if (ret < 0) {
		printf("error: %s\n", strerror(-ret));
	} else {
		printf("result[%d]: [%s]\n", ret, buf);
	}

	return 1;
}
#endif
