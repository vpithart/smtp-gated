/*
 *	compat.h
 *
 *	Copyright (C) 2004-2005 Bart³omiej Korupczynski <bartek@klolik.org>
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

#ifndef _COMPAT_H_
#define _COMPAT_H_

#ifndef _COMPAT_C_
#define EXTERN extern
#else
#define EXTERN
#endif


#if !defined(HAVE_ASPRINTF) || !defined(HAVE_VASPRINTF)
#include <stdarg.h>
#endif

/* empty */

#ifndef HAVE_STRNDUP
EXTERN char *strndup(const char *str, size_t n);
#endif

#ifndef HAVE_GETLINE
EXTERN ssize_t getline(char **lineptr, size_t *n, FILE *stream);
#endif

#ifndef HAVE_INET_ATON
EXTERN int inet_aton(const char *cp, struct in_addr *inp);
#endif

#ifndef HAVE_ASPRINTF
EXTERN int asprintf(char **ptr, const char *format, ...)
     __attribute__ ((format (printf, 2, 3)));
#endif

#ifndef HAVE_VASPRINTF
EXTERN int vasprintf(char **ptr, const char *format, va_list args)
          __attribute__ ((format (printf, 2, 0)));
#endif

#ifndef HAVE_GETLOADAVG
int getloadavg(double *list, int nelem)
#endif

#undef EXTERN

#endif

