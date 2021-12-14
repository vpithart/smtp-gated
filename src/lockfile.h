/*
 * 	lockfile.h
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


#ifndef _LOCKFILE_H_
#define _LOCKFILE_H_

#include <stdlib.h>
#include <syslog.h>
#include <netinet/in.h>

#ifndef _LOCKFILE_C_
#define EXTERN extern
#else
#define EXTERN
#endif


#define LOCK_NEVER		0x00
#define LOCK_ON_VIRUS		0x0001
#define LOCK_ON_SPAM		0x0002
#define LOCK_ON_MAX_HOST	0x0010
#define LOCK_ON_MAX_IDENT	0x0020
#define LOCK_ON_DNSBL		0x0100
#define LOCK_ON_REGEX		0x0200
#define LOCK_ON_SPF		0x0400
#define LOCK_ON_EARLYTALK	0x0800
#define LOCK_ON_RATELIMIT	0x1000
#define LOCK_ON_ANY		(LOCK_ON_VIRUS | LOCK_ON_SPAM | LOCK_ON_MAX_HOST | LOCK_ON_MAX_IDENT | LOCK_ON_DNSBL | LOCK_ON_REGEX | LOCK_ON_SPF | LOCK_ON_EARLYTALK | LOCK_ON_RATELIMIT )
EXTERN struct option_enum lock_on_list[];


EXTERN void found(struct session_t *data, int flag, found_what found_what, char *cause);
EXTERN int lockfile_present(struct session_t *data);
EXTERN int lockfile_touch(struct session_t *data, char *vir_name);
EXTERN void lockfile_action(struct session_t *data, char *cause);
EXTERN int lockfile_ident_present(struct session_t *data);

#undef EXTERN

#endif
