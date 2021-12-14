/*
 * 	proxy-helper.h
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
 * 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * 	GNU General Public License for more details.
 *
 * 	You should have received a copy of the GNU General Public License
 * 	along with this program; if not, write to the Free Software
 * 	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _PROXY_HELPER_H_
#define _PROXY_HELPER_H_

#include <sys/types.h>

#ifndef _PROXY_HELPER_C_
#define EXTERN extern
#else
#define EXTERN
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

// remote proxy helper daemon
// #define PROXY_HELPER_MAGIC	"RPHD"
#define PH_PROTO_MAGIC		('R' << 24 | 'P' << 16 | 'H' << 8 | 'D')
#define PH_PROTO_VERSION	0x0402

// request flags
#define PH_FLAG_NONE		0x0000
#define PH_TYPE_QUERY		0x0001
#define PH_TYPE_REPLY		0x0002
#define PH_RESULT_FOUND		0x0010
#define PH_RESULT_NOTFOUND	0x0020

#define PH_TYPE			(PH_TYPE_QUERY | PH_TYPE_REPLY)
#define PH_RESULT		(PH_RESULT_FOUND | PH_RESULT_NOTFOUND)


// all integers in network byte order
struct proxy_helper_query {
	uint32_t	magic;
	uint32_t	cookie;
	uint32_t	secret;
	uint16_t	version;
	uint16_t	flags;

	// filled by client, changed by server
	uint32_t	src;		// originating IP (NAT or client)
	uint32_t	dst;		// destination (proxy or MTA)
	uint16_t	src_port;
	uint16_t	dst_port;

	int8_t		ident[32];
	int8_t		mac[6];		// not used (yet)
} __attribute__ ((packed));


#endif


