/*
 *	compat.c
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


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

/* public headers */
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#ifndef HAVE_INET_ATON
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#if !defined(HAVE_ASPRINTF) || !defined(HAVE_VASPRINTF)
#include <stdarg.h>
#endif

/* private headers */

#define _COMPAT_C_
#include "compat.h"


#define VASPRINTF_START_SIZE	100


#ifndef HAVE_STRNDUP
char *strndup(const char *str, size_t n)
{
	size_t len;
	char *tmp;

	len = strlen(str);
	len = (len < n) ? len : n;

	tmp = malloc(len+1);
	if (!tmp) return NULL;

	memcpy(tmp, str, len);

	tmp[len] = '\0';
	return tmp;
}
#endif


#ifndef HAVE_GETLINE
#define GETLINE_LIMIT		8192
#warning getline size is LIMITED due to compat implementation
/* remember to init *n to 0 or sth meaningful */
ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
	if (*lineptr == NULL) {
		if (*n == 0)
			*n = GETLINE_LIMIT;
		*lineptr = malloc(*n);
		if (*lineptr == NULL) return -1;
	}

	if (fgets(*lineptr, *n, stream) == NULL) {
		return -1;
	}

	return strlen(*lineptr);
}
#endif


#ifndef HAVE_INET_ATON
/* return 0 if invalid, return !0 if valid */
int inet_aton(const char *cp, struct in_addr *inp)
{
	struct in_addr tmp;

	/* inet_aton accepts NULL as inp, but inet_pton does not */
	if (!inp) inp = &tmp;

	return (inet_pton(AF_INET, cp, inp) == 1);
}
#endif


#ifndef HAVE_ASPRINTF
int asprintf(char **ptr, const char *format, ...)
{
	va_list ap;
	int res;

	va_start(ap, format);
	res = vasprintf(ptr, format, ap);
	va_end(ap);
	
	return res;
}
#endif


#ifndef HAVE_VASPRINTF
/* return -1 if not enought memory */
int vasprintf(char **ptr, const char *format, va_list args)
{
	ssize_t size;
	int res;

	// *ptr = NULL;

	size = VASPRINTF_START_SIZE;
	for (;;) {
		*ptr = (char *) realloc(*ptr, size);
		if (*ptr == NULL) return -1;

		res = vsnprintf(*ptr, size, format, args);

		/* written up to size-1 characters (excluding '\0') => OK
		 * (res == size) means that there was not enough room 
		 * for terminating '\0' */
		if (res < size) break;

		if (res == -1) {
			// glibc < 2.0.6 returns -1 when output is truncated
			size *= 2;
			continue;
		} else {
			// glibc >= 2.1 returns string len that would be written
			// (excluding terminating '\0')
			size = res + 1;
		}
	}

	return res;
}
#endif

#ifndef HAVE_GETLOADAVG
int getloadavg(double *list, int nelem)
{
	FILE *f;
	double avg[3] = { 0.0, 0.0, 0.0 };
	int i, res = -1;;

	if ((f = fopen("/proc/loadavg", "r"))) {
		if (fscanf(f, "%lf %lf %lf", &avg[0], &avg[1], &avg[2]) <= 3) {
			fclose(f);
			for (i = 0; (i < nelem) && (i < 3); i++)
				list[i] = avg[i];
			return 0;
		} else
			fclose(f);
	}

	return -1;
}
#endif

