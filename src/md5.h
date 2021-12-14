/*
 * 	md5.h
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

#ifndef _MD5_H_
#define _MD5_H_

#include <sys/types.h>

#ifndef _MD5_C_
#define EXTERN extern
#else
#define EXTERN
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

/*
 * 	the md5_hex and md5_string_hex return the same static hash.
 * 	same applies for md5_base64 and md5_string_base64.
*/

// typedef uint32_t md5_hash_t[4];

EXTERN void md5(uint32_t hash[4], void* data, size_t len);

EXTERN char* md5_hex(void* str, size_t len);
EXTERN char* md5_base64(void* str, size_t len);

EXTERN char* md5_string_hex(char* str);
EXTERN char* md5_string_base64(char* str);

// for uint32_t a[4], b[4]:
#define MD5_EQUAL4x32(a, b)	(a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3])


#endif
