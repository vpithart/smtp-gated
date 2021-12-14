/*
 * 	spool.h
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


#ifndef _SPOOL_H_
#define _SPOOL_H_


#ifndef _SPOOL_C_
#define EXTERN extern
#else
#define EXTERN
#endif

#define LEAVE_ON_NEVER		0x00
#define LEAVE_ON_ERROR		0x01
#define LEAVE_ON_SPAM		0x02
#define LEAVE_ON_VIRUS		0x04
#define LEAVE_ON_ALWAYS		0x08


#ifndef _SPOOL_C_
EXTERN int spool_max_size;
EXTERN struct option_enum spool_leave_on_list[];
#endif

EXTERN int spool_create(struct session_t *data);
EXTERN int spool_write(struct session_t *data, void *buffer, int size);
EXTERN char* spool_scan(struct session_t *data);
EXTERN void spool_close(struct session_t *data);
EXTERN void spool_remove(struct session_t *data);


#undef EXTERN

#endif

