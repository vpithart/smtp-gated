/*
 * 	dnsbl.c
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
#define _DNSBL_C_

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include <netinet/in.h>
#include <netdb.h>

#include "conffile.h"
#include "smtp-gated.h"
#include "confvars.h"
#include "util.h"

#define DNSBL_DELIMITER		','
#define MAX_DNSBL_HOSTS		32

static char *dnsbl_host_list[MAX_DNSBL_HOSTS] = { NULL };

int dnsbl_parse()
{
	char *str, *next;
	int i;

	for (i = 0; i < MAX_DNSBL_HOSTS; i++)
		FREE_NULL(dnsbl_host_list[i]);

	if (EMPTY_STRING(config.dnsbl))
		return 0;

	for (str = config.dnsbl, i = 0; i < MAX_DNSBL_HOSTS; str = next + 1, i++) {
		next = index(str, DNSBL_DELIMITER);
		if (next) *next = '\0';

		while (*str == ' ' || *str == '\t') str++;
		dnsbl_host_list[i] = strdup(str);

		if (!next) break;
		*next = DNSBL_DELIMITER;
	}

	log_action(LOG_DEBUG, "DNSBL parser found %d list(s)", i+1);

	return 0;
}


int dnsbl_check(struct session_t *data)
{
//	data->message = "";
	char domain[1024], *dnsbl;
	struct hostent *host;
	uint32_t answer;
	int i;

	if (EMPTY_STRING(config.dnsbl)) return 0;
	if (IS_FLAG_SET(data->auth, AUTH_FLAG_ACCEPTED)) return 0;

#if 0
#error called too early to know if authenticated
	if (IS_FLAG_SET(data->auth, AUTH_FLAG_ACCEPTED) && IS_FLAG_SET(config.auth_skip, AUTH_SKIP_DNSBL)) {
		log_action(LOG_DEBUG, "DNSBL:SKIP (auth)\n");
		return 0;
	}
#endif

	for (i=0; i<MAX_DNSBL_HOSTS; i++) {
		dnsbl = dnsbl_host_list[i];
		if (!dnsbl) break;

		snprintf(domain, sizeof(domain), "%d.%d.%d.%d.%s", NIPQUAD_REV(data->origin.sin_addr.s_addr), dnsbl);
		TERMINATE_STRING(domain);

		if ((host = gethostbyname(domain)) == NULL) {
			switch (h_errno) {
				case HOST_NOT_FOUND:
				case NO_ADDRESS:
					log_action(LOG_DEBUG, "DNSBL:OK domain=%s\n", domain);
					continue;
				case NO_RECOVERY:
				case TRY_AGAIN:
				default:
					log_action(LOG_WARNING, "DNSBL:FAIL gethostbyname: %d\n", h_errno);
					continue;
			}
		}

		if (host->h_addrtype != AF_INET || host->h_length != 4) {
			log_action(LOG_WARNING, "DNSBL:FAIL gethostbyname(): h_addrtype=%d, h_length=%d\n", host->h_addrtype, host->h_length);
			return 0;
		}

		if (host->h_addr_list[0] == NULL) {
			log_action(LOG_WARNING, "DNSBL:FAIL gethostbyname(): h_addr_list == NULL\n");
			return 0;
		}

		answer = *((uint32_t *) host->h_addr_list[0]);

		asprintf(&data->message, "DNSBL: %s: %d.%d.%d.%d", dnsbl, NIPQUAD(answer));
		log_action(LOG_INFO, "DNSBL:FOUND domain=%s, answer=%d.%d.%d.%d\n", domain, NIPQUAD(answer));
		return 1;
	}

	return 0;
}
