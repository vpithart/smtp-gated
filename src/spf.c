/*
 * 	spf.c
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
#define _SPF_C_

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <spf2/spf.h>

#include "conffile.h"
#include "smtp-gated.h"
#include "confvars.h"
#include "util.h"
#include "spf.h"



static int spf_debug = 0;

/*
 * support for http://libspf2.org
*/

struct option_enum spf_list[] = {
	{ "incoming", SPF_INCOMING },
	{ "outgoing", SPF_OUTGOING },
	{ "fixed", SPF_FIXED },
	{ "off", SPF_OFF },
    { NULL }
};

#if 0
static char* spf_result_str(int res)
{
	switch (res) {
		case SPF_RESULT_INVALID: return "invalid";
		case SPF_RESULT_NEUTRAL: return "neutral";
		case SPF_RESULT_PASS: return "pass";
		case SPF_RESULT_FAIL: return "fail";
		case SPF_RESULT_SOFTFAIL: return "softfail";
		case SPF_RESULT_NONE: return "none";
		case SPF_RESULT_TEMPERROR: return "temperror";
		case SPF_RESULT_PERMERROR: return "temperror";
		default: return "-";
	}
}
#endif


const char* spf_version()
{
	static char version[32];

	snprintf(version, sizeof(version), "libspf2 %d.%d.%d",
		SPF_LIB_VERSION_MAJOR, SPF_LIB_VERSION_MINOR, SPF_LIB_VERSION_PATCH);
	TERMINATE_STRING(version);

	return version;
}


spf_result spf_check(struct session_t *data, char* mailfrom)
{
	SPF_server_t *spf_server = NULL;
	SPF_request_t *spf_request = NULL;
	SPF_response_t *spf_response = NULL;
	struct in_addr ip;
	int ret = SPF_ERROR;
	int res;

	switch (config.spf) {
		case SPF_OFF:
			return SPF_SKIP;
		case SPF_OUTGOING:
			ip = data->local.sin_addr;
			break;
		case SPF_INCOMING:
			ip = data->origin.sin_addr;
			break;
		case SPF_FIXED:
			inet_aton(config.spf_fixed_ip, &ip);
			break;
		default:
			log_action(LOG_CRIT, "spf: unknown type [%d]", config.spf);
			return SPF_SKIP;
	}

	if (IS_FLAG_SET(data->auth, AUTH_FLAG_ACCEPTED)) return SPF_SKIP;

	SHARED_CONN_STATUS(state, CONN_SPF);
	if ((spf_server = SPF_server_new(SPF_DNS_CACHE, spf_debug)) == NULL) {
		log_action(LOG_DEBUG, "SPF_server_new failed");
		goto out;
	}
	
	if ((spf_request = SPF_request_new(spf_server)) == NULL) {
		log_action(LOG_DEBUG, "SPF_request_new failed");
		goto out;
	}

//	log_action(LOG_DEBUG, "spf:rec_dom %s", config.proxy_name);
	if ((res = SPF_server_set_rec_dom(spf_server, config.proxy_name))) {
		log_action(LOG_DEBUG, "SPF_server_set_rec_dom error[%d]: %s", res, SPF_strerror(res));
		goto out;
	}
	
//	log_action(LOG_DEBUG, "spf:ip %d.%d.%d.%d", NIPQUAD(ip));
	if ((res = SPF_request_set_ipv4(spf_request, ip))) {
		log_action(LOG_DEBUG, "SPF_request_set_ipv4 error[%d]: %s", res, SPF_strerror(res));
		goto out;
	}
	
//	log_action(LOG_DEBUG, "spf:helo %s", data->helo);
	if ((res = SPF_request_set_helo_dom(spf_request, (data->helo) ? data->helo : ""))) {
		log_action(LOG_DEBUG, "SPF_request_set_helo_dom failed[%d]: %s", res, SPF_strerror(res));
		goto out;
	}

//	log_action(LOG_DEBUG, "spf:mailfrom %s", mailfrom);
	if ((res = SPF_request_set_env_from(spf_request, mailfrom))) {
		log_action(LOG_DEBUG, "SPF_request_set_env_from error[%d]: %s", res, SPF_strerror(res));
		goto out;
	}

	if ((res = SPF_request_query_mailfrom(spf_request, &spf_response))) {
		if (res == SPF_E_NOT_SPF) {
			log_action(LOG_DEBUG, "SPF:none ip=%d.%d.%d.%d, helo=%s, from=%s",
				NIPQUAD(ip), data->helo, mailfrom);
			ret = SPF_SKIP;
			goto out;
		}
		log_action(LOG_DEBUG, "SPF_request_query_mailfrom error[%d]: %s", res, SPF_strerror(res));
		goto out;
	}
	
	res = SPF_response_result(spf_response);
	log_action(LOG_DEBUG, "SPF:%s ip=%d.%d.%d.%d, helo=%s, from=%s",
		SPF_strresult(res), NIPQUAD(ip), data->helo, mailfrom);

	switch (res) {
		case SPF_RESULT_PASS:
		case SPF_RESULT_NEUTRAL:
			ret =  SPF_PASS;
			break;
		case SPF_RESULT_SOFTFAIL:
			ret = SPF_PASS;
			break;
		case SPF_RESULT_FAIL:
			ret = SPF_FAIL;
			break;
		case SPF_RESULT_TEMPERROR:
			ret = SPF_PASS;
			break;
		case SPF_RESULT_PERMERROR:
			ret = SPF_ERROR;
			break;
		case SPF_RESULT_NONE:
			ret = SPF_INVALID;
			break;
		default:
			BUG("unknown spf result: %d\n", res);
			ret = SPF_INVALID;
			break;
	}

out:
//	if (spf_response) SPF_response_free(spf_response);
	if (spf_request) SPF_request_free(spf_request);
	if (spf_server) SPF_server_free(spf_server);
	return ret;
}


