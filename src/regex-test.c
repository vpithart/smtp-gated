/*
 *	regex-test.c
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

#include <stdio.h>
#include <unistd.h>
#include <sys/un.h>
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#include <syslog.h>
#include <errno.h>
#include <string.h>


#ifdef HAVE_PCRE_H
#include <pcre.h>
#elif HAVE_PCRE_PCRE_H
#include <pcre/pcre.h>
#endif



int main(int argc, char* argv[])
{
	pcre *pc;
	char *expr, *str;
	const char *errstr;
	int erroffs, res;

	printf("PCRE version: %s\n", pcre_version());

	if (argc < 3) {
		printf("regex-test regex string\n");
		return 1;
	}

	expr = argv[1];
	str = argv[2];

	printf("expr: [%s]\n str: [%s]\n", expr, str);

	pc = pcre_compile(expr, 0, &errstr, &erroffs, NULL);
	if (!pc) {
		printf("pcre_compile[%d]: %s\n", erroffs, errstr);
		return 1;
	}

	res = pcre_exec(pc, NULL, str, strlen(str), 0, 0, NULL, 0);
	printf("pcre_exec: %d\n", res);

	pcre_free(pc);

	return 0;
}


