/*
 *	lookup.c
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#define _LOOKUP_C_


#include <sys/types.h>
#include <sys/socket.h>

#ifdef USE_NAT_PF
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#endif

#ifdef USE_NAT_IPFILTER
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <netinet/ipl.h>
#include <netinet/ip_compat.h>
#include <netinet/ip_fil.h>
#include <netinet/ip_nat.h>
#include <netinet/ip_state.h>
#include <netinet/ip_proxy.h>
#ifndef IPNAT_NAME
#define IPNAT_NAME IPL_NAT
#endif
#endif

#include <sys/un.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#ifdef HAVE_LINUX_NETFILTER_IPV4_H
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#endif

#include "conffile.h"
#include "smtp-gated.h"
#include "confvars.h"
#include "smtp-gated.h"
#include "lookup.h"
#include "lockfile.h"
#include "proxy-helper.h"
#include "util.h"
#include "md5.h"


static char *msg_ok = "OK";

// enum LOOKUP_* in lookup.h
char **lookup_errors[] = {
	&config.msg_lookup_unknown,	// LOOKUP_UNKNOWN
	&msg_ok,			// LOOKUP_OK
	&config.msg_lookup_notfound,	// LOOKUP_NOTFOUND
	&config.msg_lookup_timeout,	// LOOKUP_TIMEOUT
	&config.msg_lookup_mismatch,	// LOOKUP_MISMATCH
	&config.msg_lookup_nomem	// LOOKUP_NOMEM
};


/*
 *	will return only if ok
*/
#ifdef USE_SHARED_MEM
void check_per_ident_limit(struct session_t *data)
{
	int i;

	data->ident_count = 0;
	untaint(data->ident, sizeof(data->ident));
	// strncpy zeruje pozostalosc stringa,
	strncpy(connections[child_slot].ident, data->ident, sizeof(connections[child_slot].ident));
	TERMINATE_STRING(connections[child_slot].ident);
	SHARED_CONN_STATUS(ident_ok, 1);

	for(i=0; i<max_connections_real; i++) {
		// if (!connections[i].pid) continue;
		if (!connections[i].ident_ok) continue;
		if (connections[i].src != SIN_TO_UINT32(data->origin.sin_addr)) continue;
		if (strcmp(connections[i].ident, data->ident) != 0) continue;

		data->ident_count++;
	}

	if (data->ident_count > config.max_per_ident) {
		/* no need to be nice for flooder */
		response(data, CONN_REJ_ER, "%s %s\r\n", config.proxy_name, config.msg_max_per_ident);
		SAFE_CLOSE(data->client);
		SHARED_STATS_INC(rejects_ident);
		log_action(LOG_INFO, "Rejecting (ident %d) connection from %s:%d [%s]",
			data->ident_count, data->origin_str, ntohs(data->origin.sin_port), data->ident);
		/* lockfile_ident_present needed for data->lockfile setup */
		found(data, LOCK_ON_MAX_IDENT, FOUND_MAX_IDENT, "MAX_IDENT");
		cleanup();
		exit(0);
	}
}
#endif /* USE_SHARED_MEM */

/*
 * 	used data members:
 * 	- client
 * 	- target, target_port, target_str
 * 	- target
*/


#ifdef USE_NAT_NETFILTER
static int lookup_netfilter(struct session_t *data)
{
	socklen_t size;

	data->target.sin_family = AF_INET;
	size = (socklen_t) sizeof(data->target);

	if (getsockopt(data->client, IPPROTO_IP, SO_ORIGINAL_DST, &data->target, &size) != 0)
		return -1;

	snprintf(data->target_str, sizeof(data->target_str), "%s", inet_ntoa(data->target.sin_addr));
	TERMINATE_STRING(data->target_str);

	return LOOKUP_OK;
} /* lookup_netfilter() */
#endif

#ifdef USE_NAT_TPROXY
/*
	if we use lookup_netfilter code for tproxy, we get:
	NEW (1/0) on=m.t.a.1:25, src=62.*.*.*:1708, ident=, dst=m.t.a.1:25, id=1277124162.30108
	so if local IP is spoofed, then it should be enough to just use local IP:PORT as target MTA
	this way we don't need netfilter/NAT at all, so no need to even load nf_nat
*/
static int lookup_tproxy(struct session_t *data)
{
	data->target = data->local;

	snprintf(data->target_str, sizeof(data->target_str), "%s", inet_ntoa(data->target.sin_addr));
	TERMINATE_STRING(data->target_str);

	return LOOKUP_OK;
} /* lookup_tproxy() */
#endif


static int lookup_getsockname(struct session_t *data)
{
	socklen_t size;

	data->target.sin_family = AF_INET;
	size = (socklen_t) sizeof(data->target);

	if (getsockname(data->client, (struct sockaddr *) &data->target, &size) != 0)
		return -1;

	snprintf(data->target_str, sizeof(data->target_str), "%s", inet_ntoa(data->target.sin_addr));
	TERMINATE_STRING(data->target_str);

	return LOOKUP_OK;
} /* lookup_getsockname() */

#ifdef USE_NAT_PF
static int lookup_pf(struct session_t *data)
{
	struct pfioc_natlook nl;
	int dev, err;

	memset(&nl, 0, sizeof(struct pfioc_natlook));
	nl.saddr.v4.s_addr = data->origin.sin_addr.s_addr;
	nl.sport = data->origin.sin_port;
	nl.daddr.v4.s_addr = data->local.sin_addr.s_addr;
	nl.dport = data->local.sin_port;
	nl.af = AF_INET;
	nl.proto = IPPROTO_TCP;
	nl.direction = PF_OUT;

	// maybe we could open this at startup (even while we are stiil root)?
	// but there would be horrible mess if many subprocesses should access
	// it at the same time. locking? noooo...
	// one connection per slot? maybe... but this doesn't look nice either.

	if ((dev = open("/dev/pf", O_RDWR)) == -1) {
		log_action(LOG_DEBUG, "%s:open():%s", __FUNCTION__, strerror(errno));
		return -1;
	}

	if (ioctl(dev, DIOCNATLOOK, &nl)) {
		if (errno == ENOENT) {
			SAFE_CLOSE(dev);
			errno = 0;
			return LOOKUP_NOTFOUND;
		}
		err = errno;
		log_action(LOG_DEBUG, "%s:ioctl():%s", __FUNCTION__, strerror(errno));
		SAFE_CLOSE(dev);
		errno = err;
		return -1;
	}

	SAFE_CLOSE(dev);

	data->target.sin_addr.s_addr = nl.rdaddr.v4.s_addr;
	data->target.sin_port = nl.rdport;

	snprintf(data->target_str, sizeof(data->target_str), "%s", inet_ntoa(data->target.sin_addr));
	TERMINATE_STRING(data->target_str);

	return LOOKUP_OK;
} /* lookup_pf */
#endif

#ifdef USE_NAT_IPFILTER
static int lookup_ipfilter(struct session_t *data)
{
#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	ipfobj_t ipfobj;
#endif
	struct sockaddr_in sin, sloc;
	natlookup_t natlookup;
	int res, namelen, ipnat_fd = -1;

	namelen = sizeof(sin);
	if (getpeername(data->client, (struct sockaddr *)&sin, &namelen) == -1)
		return -1;

	namelen = sizeof(sloc);
	if (getsockname(data->client, (struct sockaddr *)&sloc, &namelen) == -1)
		return -1;

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	memset(&ipfobj, 0, sizeof(ipfobj));
	ipfobj.ipfo_rev = IPFILTER_VERSION;
	ipfobj.ipfo_size = sizeof(natlookup);
	ipfobj.ipfo_ptr = &natlookup;
	ipfobj.ipfo_type = IPFOBJ_NATLOOKUP;
#endif

	memset(&natlookup, 0, sizeof(natlookup));
	natlookup.nl_inip = sloc.sin_addr;
	natlookup.nl_outip = sin.sin_addr;
	natlookup.nl_flags = IPN_TCP;
	natlookup.nl_inport = sloc.sin_port;
	natlookup.nl_outport = sin.sin_port;

	if ((ipnat_fd = open(IPNAT_NAME, O_RDONLY)) == -1) {
		log_action(LOG_DEBUG, "%s:open():%s", __FUNCTION__, strerror(errno));
		return -1;
	}
#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	if (ioctl(ipnat_fd, SIOCGNATL, &ipfobj) == -1) {
#else
	if (ioctl(ipnat_fd, SIOCGNATL, &natlookup) == -1) {
#endif
		res = errno;
		log_action(LOG_DEBUG, "%s:ioctl():%s", __FUNCTION__, strerror(errno));
		SAFE_CLOSE(ipnat_fd);
		errno = res;
		return -1;
	}
	SAFE_CLOSE(ipnat_fd);

	data->target.sin_family = AF_INET;
	data->target.sin_port = natlookup.nl_realport;
	data->target.sin_addr = natlookup.nl_realip;

	snprintf(data->target_str, sizeof(data->target_str), "%s", inet_ntoa(data->target.sin_addr));
	TERMINATE_STRING(data->target_str);

	return LOOKUP_OK;
}
#endif


static int lookup_remote(struct session_t *data)
{
	char buf[1024];
	char ident_tmp[IDENT_SIZE+1];	// fixed 128!
	int res;
	size_t pos;
	int rport, lport;
	int client_port, local_port, target_port;
	int ip1, ip2, ip3, ip4;
	int sock;

	client_port = (int) ntohs(data->origin.sin_port);
	local_port = config.port;
	SET_TIMEOUT(config.timeout_lookup);

	if ((sock = connect_host(data->origin, config.remote_port, data->local, NULL, NULL)) == -1)
		goto fail;

	if (fdprintf(sock, "%d , %d\r\n", client_port, local_port) == -1) {
		if (errno == EINTR) errno = ETIMEDOUT;
		goto fail;
	}

	for (pos=0;;) {
		if (timedout) {
			CLEAR_TIMEOUT();
			errno = ETIMEDOUT;
			goto fail;
		}
		if ((res = read(sock, buf+pos, sizeof(buf)-pos)) == -1) {
			goto fail;
		}
		if (res == 0) break;
		pos += res;
	}

	buf[(pos < sizeof(buf)) ? pos : sizeof(buf)-1] = '\0';

	SAFE_CLOSE(sock);
//	sock = -1;
	CLEAR_TIMEOUT();

#if IDENT_SIZE != 20
#warning Please update numbers in two places:
#warning 1. in sscanf format below (last number)
#warning 2. in #if above
#error Both of them must much IDENT_SIZE!
#endif
	res = sscanf(buf, "%d , %d : ORIGIN : %d.%d.%d.%d : %d : %20s",
		&rport, &lport, &ip1, &ip2, &ip3, &ip4, &target_port, ident_tmp);

	untaint(buf, sizeof(buf));

	if (res != 8) goto lookup_mismatch;
	TERMINATE_STRING(ident_tmp);

	if ((rport != client_port) || (lport != local_port) ||
		(target_port < 0) || (target_port > 65535) ||
		(ip1 < 0) || (ip1 > 255) || (ip2 < 0) || (ip2 > 255) ||
		(ip3 < 0) || (ip3 > 255) || (ip4 < 0) || (ip3 > 255))
		goto lookup_mismatch;

	res = snprintf(data->target_str, sizeof(data->target_str), "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
	if (res == -1 || res > sizeof(data->target_str)) return LOOKUP_NOMEM;

	TERMINATE_STRING(data->target_str);

	data->target.sin_family = AF_INET;
	data->target.sin_port = htons(target_port);
	if (!inet_aton(data->target_str, &data->target.sin_addr))
		goto lookup_mismatch;

	strncpy(data->ident, ident_tmp, sizeof(data->ident));
	TERMINATE_STRING(data->ident);

	// LOOKUP_RFC, LOOKUP_EXTENDED
	return LOOKUP_OK;

lookup_mismatch:
	log_action(LOG_ERR, "Lookup mismatch from %s [%s]", data->origin_str, buf);
	return LOOKUP_MISMATCH;

fail:
	res = errno;
	CLEAR_TIMEOUT();
	if (sock != -1) SAFE_CLOSE(sock);

	if (res == EINTR || res == ETIMEDOUT) return LOOKUP_TIMEOUT;
	errno = res;
	return -1;
} /* lookup_remote() */



static int lookup_remote_udp(struct session_t *data)
{
	fd_set rfds;
	struct timeval tv;
	struct proxy_helper_query query, response;
	struct sockaddr_in src, helper, orig;
	socklen_t orig_len, helper_len;
	ssize_t size;
	int sock;
	int res, retry;


	memset(&query, 0, sizeof(query));
	memset(&response, 0, sizeof(response));

	query.magic = htonl(PH_PROTO_MAGIC);
	query.cookie = random();
	query.secret = htonl(config.remote_udp_secret);
	query.version = htons(PH_PROTO_VERSION);
	query.flags = htons(PH_TYPE_QUERY);

	query.src = data->origin.sin_addr.s_addr;
	query.src_port = data->origin.sin_port;
	query.dst = data->local.sin_addr.s_addr;
	query.dst_port = data->local.sin_port;

	// query
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		LOG_FUNC_ERR("socket");
		goto fail;
	}

	src.sin_family = AF_INET;
	src = data->local;
	src.sin_port = 0;
	if (bind(sock, (struct sockaddr *) &src, sizeof(src)) != 0) {
		LOG_FUNC_ERR("bind");
		goto fail;
	}

	helper = data->origin;
	helper.sin_family = AF_INET;
	helper.sin_port = htons(config.remote_port);

	size = -1;
	for (retry = config.remote_udp_retries; retry > 0; retry--) {
		helper_len = ((size_t) &response.ident - (size_t) &response);
#if 0
		log_action(LOG_DEBUG, "UDP query: host=[%d.%d.%d.%d]:%d, src=[%d.%d.%d.%d]:%d, dst=[%d.%d.%d.%d]:%d",
			NIPQUAD(helper.sin_addr.s_addr), ntohs(helper.sin_port),
			NIPQUAD(query.src), ntohs(query.src_port),
			NIPQUAD(query.dst), ntohs(query.dst_port));
#endif
		// this timeout probably does not really do anything, sendto() is quite non-problematic
		SET_TIMEOUT(config.timeout_lookup);
		if ((size = sendto(sock, &query, sizeof(query), 0, (struct sockaddr *) &helper, helper_len)) == -1) {
			LOG_FUNC_ERR("sendto");
			goto fail;
		}
		CLEAR_TIMEOUT();
#if 0
		if (size != orig_len) {
			log_action(LOG_DEBUG, "sendto(%d) returned %d", orig_len, size);
			errno = EINVAL;
			goto fail;
		}
#endif

		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		tv.tv_sec = config.timeout_lookup;
		tv.tv_usec = 0;

		if ((res = select(sock+1, &rfds, NULL, NULL, &tv)) == -1) {
			LOG_FUNC_ERR("select");
			goto fail;
		}

		// timeout
		if (res == 0) continue;

		// let's look what we've got
		orig_len = sizeof(orig);
		if ((size = recvfrom(sock, &response, sizeof(response), 0, (struct sockaddr *) &orig, &orig_len)) == -1) {
			if (errno == EINTR) continue;
			LOG_FUNC_ERR("recvfrom");
			goto fail;
		}

#if 0
		// verify if UDP response source matches helper address
		if (orig.sin_addr.s_addr != helper.sin_addr.s_addr) {
			log_action(LOG_ERR, "received response from [%d.%d.%d.%d] instead of [%d.%d.%d.%d], droppped",
				NIPQUAD(orig.sin_addr.s_addr), NIPQUAD(helper.sin_addr.s_addr));
			continue;
		}
#endif

		if (query.magic != response.magic || query.cookie != response.cookie) {
			log_action(LOG_NOTICE, "received invalid response: magic=0x%08x/0x%08x, cookie=0x%08x/0x%08x",
				ntohl(query.magic), ntohl(response.magic),
				ntohl(query.cookie), ntohl(response.cookie));
			continue;
		}
		break;
	}

	SAFE_CLOSE(sock);
	TERMINATE_STRING(response.ident);

	if (size == -1) {
		errno = ETIMEDOUT;
		goto fail;
	}

#if 0
	log_action(LOG_DEBUG, "UDP response: host=[%d.%d.%d.%d]:%d, src=[%d.%d.%d.%d]:%d, dst=[%d.%d.%d.%d]:%d, ident=%s",
		NIPQUAD(orig.sin_addr.s_addr), ntohs(orig.sin_port),
		NIPQUAD(response.src), ntohs(response.src_port),
		NIPQUAD(response.dst), ntohs(response.dst_port),
		response.ident);
#endif

//	if (orig_len != sizeof(response)) return LOOKUP_MISMATCH;
	if (query.version != response.version) return LOOKUP_MISMATCH;

	if ((ntohs(response.flags) & PH_TYPE) != PH_TYPE_REPLY) return LOOKUP_MISMATCH;
	if ((ntohs(response.flags) & PH_RESULT) != PH_RESULT_FOUND) return LOOKUP_NOTFOUND;
//	res = memcmp(&query, &response, ((size_t) &query.dst) - ((size_t) &query));
//	if (res != 0) return LOOKUP_MISMATCH;

	// copy data
	data->target.sin_family = AF_INET;
	data->target.sin_addr.s_addr = response.dst;
	data->target.sin_port = response.dst_port;

	strncpy(data->target_str, inet_ntoa(data->target.sin_addr), sizeof(data->target_str));
	TERMINATE_STRING(data->target_str);

	strncpy(data->ident, (char *) response.ident, sizeof(data->ident));
	TERMINATE_STRING(data->ident);

	return LOOKUP_OK;

fail:
	res = errno;
	CLEAR_TIMEOUT();
	if (sock != -1) SAFE_CLOSE(sock);
	errno = res;
	return -1;
} /* lookup_remote_udp */



/*
	identyfikacja adres serwera oryginalnego
	=0	ok
	-1	error, (->errno)
	>0	LOOKUP_x
*/

int target_lookup(struct session_t *data)
{
	int res;

	res = LOOKUP_UNKNOWN;

	// lookups
	// must fill: target, target_str, ident
	switch (data->mode) {
#ifdef USE_NAT_PF
	case MODE_PF:
		res = lookup_pf(data);
		break;
#endif
#ifdef USE_NAT_TPROXY
	case MODE_TPROXY:
		res = lookup_tproxy(data);
		break;
#endif
#ifdef USE_NAT_NETFILTER
	case MODE_NETFILTER:
		res = lookup_netfilter(data);
		// + normalny ident?
		break;
#endif
#ifdef USE_NAT_IPFW
	case MODE_IPFW:
		res = lookup_getsockname(data);
		break;
#endif
#ifdef USE_NAT_IPFILTER
	case MODE_IPFILTER:
		res = lookup_ipfilter(data);
		break;
#endif
	case MODE_GETSOCKNAME: // same code as for ipfw
		res = lookup_getsockname(data);
		break;
	case MODE_FIXED:
	case MODE_FIXED_XCLIENT:
		strncpy(data->target_str, config.fixed_server, sizeof(data->target_str));
		TERMINATE_STRING(data->target_str);

		data->target.sin_family = AF_INET;
		data->target.sin_port = htons(config.fixed_server_port);
		if (!inet_aton(data->target_str, &data->target.sin_addr))
			res = LOOKUP_MISMATCH;
		// normalny ident?
		res = LOOKUP_OK;
		break;

	case MODE_REMOTE:
		res = lookup_remote(data);
#ifdef USE_SHARED_MEM
		if (res == LOOKUP_OK) check_per_ident_limit(data);
#endif
		break;

	case MODE_REMOTE_UDP:
		res = lookup_remote_udp(data);
#ifdef USE_SHARED_MEM
		if (res == LOOKUP_OK) check_per_ident_limit(data);
#endif
		break;

	default:
		BUG("Unknown mode: %d", data->mode);
		break;
	}

	if (res == -1) {
		res = errno;
		helo(data->client);
		wait_for_quit(data, "%s: %s", config.msg_lookup_failed, strerror(res));
		exit(5);
	} else if (res != LOOKUP_OK) {
		helo(data->client);
		wait_for_quit(data, "%s: %s", config.msg_lookup_failed, *lookup_errors[res]);
		exit(5);
	}

	return 1;
} /* target_lookup() */
