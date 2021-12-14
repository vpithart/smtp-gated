/*
 *	dspam-test.c
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "util.h"


#ifdef HAVE_LIBDSPAM_H
#include <libdspam.h>
#elif HAVE_DSPAM_LIBDSPAM_H
#include <dspam/libdspam.h>
#endif


char* load_file(char *filename, int max_size)
{
	struct stat st;
	char *message;
	int pos, size, file;

	if ((file = open(filename, O_RDONLY)) == -1) {
		printf("open(%s): %s\n", filename, strerror(errno));
		return NULL;
	}

	if (fstat(file, &st) == -1) {
		printf("fstat(): %s\n", strerror(errno));
		return NULL;
	}

	max_size = (max_size > 0) ? min(st.st_size, max_size) : st.st_size;
	message = malloc(max_size + 1);
	if (!message) {
		printf("malloc(): NULL\n");
		return NULL;
	}

	memset(message, '\0', max_size);
	for (pos=0;;) {
		if ((size = read(file, message+pos, max_size-pos)) == -1) {
			printf("read(): %s\n", strerror(errno));
			free(message);
			return NULL;
		}
		pos += size;
		if (size == 0) break;
	}

	close(file);
	message[max_size] = '\0';

	return message;
}

char* dspam_result_string(int res)
{
	switch (res) {
		case DSR_ISSPAM: return "DSR_ISSPAM";
		case DSR_ISINNOCENT: return "DSR_ISINNOCENT";
#ifdef DSR_ISWHITELISTED
		case DSR_ISWHITELISTED: return "DSR_ISWHITELISTED";
#endif					 
		default: return strerror(res);
	}
}



int main(int argc, char* argv[])
{
	DSPAM_CTX *dsc;
	char *msg = NULL;
	char *user = NULL, *group = NULL, *storage = NULL, *filename = NULL;
	int i, res;


	for (i=1; i<argc; i++) {
		if (!strcmp(argv[i], "-u")) {
			user = argv[++i];
		} else if (!strcmp(argv[i], "-g")) {
			group = argv[++i];
		} else if (!strcmp(argv[i], "-s")) {
			storage = argv[++i];
		} else if (!strcmp(argv[i], "-f")) {
			filename = argv[++i];
		} else if (!strcmp(argv[i], "-h")) {
			printf("usage: dspam-test -u USER -g GROUP -s STORAGE_PATH -f FILENAME\n");
			return 101;
		} else {
			printf("unknown option: %s\n", argv[i]);
			return 101;
		}
	}

	printf("user: %s\ngroup: %s\nstorage: %s\nfilename: %s\n",
		user, group, storage, filename);
	
	printf("init()\n");
	if ((dsc = dspam_init(user, group, storage, DSM_PROCESS, 0)) == NULL) {
		printf("dspam_init(): NULL\n");
		return 1;
	}

	printf("load_file(%s)\n", filename);
	msg = load_file(filename, 1000000);
	if (!msg) return 1;
	
	printf("dspam_process()\n");
	res = dspam_process(dsc, msg);
	printf("dspam_process(): %s\n", dspam_result_string(res));

	printf("dspam_destroy()\n");
	dspam_destroy(dsc);
	return 0;
}


