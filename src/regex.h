/*
 * 	regex.h
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


#ifndef _REGEX_H_
#define _REGEX_H_


#ifndef _REGEX_C_
#define EXTERN extern
#else
#define EXTERN
#endif


EXTERN const char* regex_version();
EXTERN int regex_parse();
EXTERN int regex_check_helo(char *str);
EXTERN int regex_check_mail_from(char *str);
EXTERN int regex_check_rcpt_to(char *str);


#undef EXTERN

#endif

