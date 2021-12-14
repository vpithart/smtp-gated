/*
 * 	spf.h
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


#ifndef _SPF_H_
#define _SPF_H_


#ifndef _SPF_C_
#define EXTERN extern
#else
#define EXTERN
#endif

typedef enum { SPF_INVALID = 0, SPF_NONE, SPF_SKIP, SPF_ERROR, SPF_PASS, SPF_FAIL } spf_result;

enum { SPF_OFF = 0, SPF_INCOMING, SPF_OUTGOING, SPF_FIXED };


#ifndef _SPF_C_
EXTERN struct option_enum spf_list[];
#endif

EXTERN const char* spf_version();
EXTERN spf_result spf_check(struct session_t *data, char* mailfrom);


#undef EXTERN
#endif

