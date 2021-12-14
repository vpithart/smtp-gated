/*
 *	conffile.c
 *
 *	Copyright (C) 2004-2005 Bart�omiej Korupczynski <bartek@klolik.org>
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

#ifdef HAVE_ERR_H
#include <err.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>



#define _CONFFILE_C_
#include "conffile.h"
#include "smtp-gated.h"
#include "util.h"
#include "compat.h"


//char config_error[128];
//#define LOG_ACTION(a...) log_action(a)


/*
 * 	setting defaults
*/

int config_set_defaults(struct config_option config_options[])
{
	struct config_option *option;

	for (option = config_options; ; option++) {
		// flags
		switch (option->type) {
		case CONFIG_IP4:
		case CONFIG_STR:
			if (IS_FLAG_CLEARED(option->flags, CONF_FLAG_EMPTY) && EMPTY_STRING(option->def.s)) {
				log_action(LOG_CRIT, "defaults[%s]: empty value not permitted!", option->name);
				return -100;
			}
			break;
		default:
			break;
		}

		// copy
		switch (option->type) {
		case CONFIG_INT:
		case CONFIG_UINT:
		case CONFIG_BOOL:
		case CONFIG_PORT:
		case CONFIG_ENUM:
			*((int *) option->val) = option->def.i;
			break;

		case CONFIG_DOUBLE:
			*((double *) option->val) = option->def.d;
			break;

		case CONFIG_IP4:
			// if (!inet_aton(option->def.s, NULL) && !EMPTY_STRING(option->def.s)) {
			if (!EMPTY_STRING(option->def.s) && !inet_aton(option->def.s, NULL)) {
				log_action(LOG_CRIT, "defaults[%s]: invalid IP [%s]", option->name, option->def.s);
				return -101;
			}
			/* no-break */
		case CONFIG_STR:
			if (*((char **) option->val)) free(*((char **) option->val));
			*((char **)option->val) = strdup(option->def.s);
			if (!*((char **) option->val)) {
				log_action(LOG_CRIT, "defaults[%s]: strdup() failed!", option->name);
				return -102;
			}
			break;

		case CONFIG_END:
			return 0;

		default:
			BUG("defaults[%s]: unknown type [%d]", option->name, option->type);
			return -200;
		}
	}

	return 0;
}

/*
 *	option specific
*/

/*
 * multiple-valued (bitmask) options must be sorted descending
*/

static int find_enum_value(struct config_option *option, char *name)
{
	struct option_enum *list;
	int *value = (int *) option->val;
	char *current, *next;
	int tmp;


	if (!name) return 0;

	// check for integer value
	if (sscanf(name, "%i", &tmp) == 1) {
		if (IS_FLAG_SET(option->flags, CONF_FLAG_ARBITRARY)) {
			*value = tmp;
			return 1;
		}

		for (list = option->specific; list->name != NULL; list++) {
			if (list->value != tmp) continue;
			*value = tmp;
			return 1;
		}
	}

	*value =0;
	for (current=name; current != NULL; current = next) {
		if ((next = strchr(current, ',')) != NULL) {
			if (IS_FLAG_CLEARED(option->flags, CONF_FLAG_BITMAP)) return 0;

			*next++ = '\0';
			while (*next == ' ' || *next == '\t') next++;
		}

		for (list = option->specific; list->name != NULL; list++) {
			if (strcmp(list->name, current) != 0) continue;

			*value |= list->value;
			break;
		}

		// not found
		if (!list->name) return 0;
	}

	return 1;
}

static void print_enum_name(struct config_option *option, int value)
{
	struct option_enum *list;
	int prev = 0;

//	printf("[%d] ", value);
	if (IS_FLAG_SET(option->flags, CONF_FLAG_BITMAP)) {
		for (list = option->specific; list->name != NULL; list++) {
			if ((list->value & value) == list->value) {
				if (prev) printf(",");
				prev = 1;
				printf("%s", list->name);
				value &= ~list->value;
				if (!value) return;
			}
		}
	} else {
		for (list = option->specific; list->name != NULL; list++) {
			if (list->value != value) continue;

			printf("%s", list->name);
			return;
		}

		// no match; print numerical value
		printf("%d", value);
	}
}



/*
 * 	parsers
*/

static int parse_value(struct config_option *option, char *string)
{
	int res;

	if (IS_FLAG_CLEARED(option->flags, CONF_FLAG_EMPTY) && EMPTY_STRING(string)) return -1;

	switch (option->type) {
	case CONFIG_INT:
	case CONFIG_UINT:
		res = sscanf(string, "%i", (int *) option->val);
		if (res != 1) return -1;
		break;

	case CONFIG_DOUBLE:
		res = sscanf(string, "%lf", (double *) option->val);
		if (res != 1) return -1;
		break;

	case CONFIG_IP4:
		if (!inet_aton(string, NULL)) return -1;
		// copy
	case CONFIG_STR:
		if (*((char **) option->val)) free(*((char **) option->val));
		*((char **)option->val) = strdup(string);
		if (!*((char **) option->val)) return -1;
		break;

	case CONFIG_PORT:
		if (IS_FLAG_SET(option->flags, CONF_FLAG_MINUS_1) && (strcmp(string, "-1") == 0)) {
			*((int *) option->val) = -1;
			break;
		}
		res = sscanf(string, "%i", (int *) option->val);
		if (res != 1) return -1;
		if (*((int *) option->val) < 1 || *((int *) option->val) > 65535) return -1;
		break;

	case CONFIG_BOOL:
		if (strcmp(string, "1") == 0 || strcasecmp(string, "yes") == 0 || strcasecmp(string, "on") == 0) {
			*((int *) option->val) = 1;
			break;
		}
		if (strcmp(string, "0") == 0 || strcasecmp(string, "no") == 0|| strcasecmp(string, "off") == 0) {
			*((int *) option->val) = 0;
			break;
		}
		return -1;

	case CONFIG_ENUM:
		if (!find_enum_value(option, string)) return -1;
		break;

	default:
		BUG("parse_value[%s]: unknown type [%d]", option->name, option->type);
		return -200;
	}

	return 0;
}


/*
 * 	readine config file
*/

int read_config(struct config_option config_options[], char *filename)
{
	FILE *f;
	int res, line, found;
	struct config_option *option;
	char *value, *valend, *valend_space;
	char *buf, *name;
	size_t len;


	if (config_set_defaults(config_options) != 0) return -4;
	if (!filename) return 0;

	f = fopen(filename, "r");
	if (!f) {
		log_action(LOG_CRIT, "Error opening config file %s: %s", filename, strerror(errno));
		return -1;
	}

//	log_action(LOG_DEBUG, "Reading config from %s", filename);
	buf = NULL;
	line = 0;
	len = 0;
	while (!feof(f)) {
		res = getline(&buf, &len, f);
		if (res == -1) break;
		if (buf == NULL) {
			log_action(LOG_CRIT, "getline() buf=NULL");
			return -3;
		}
		line++;

		// skip white space(s)
		for (name=buf; *name==' ' || *name=='\t'; name++);

		// skip comments and empty lines
		if ((name[0] == '\0') || (name[0] == '#') || (name[0] == ';') ||
			(name[0] == '\r') || (name[0] == '\n'))
			continue;

		// skip to the end of option name and terminate it with '\0'
		for (value=name;; value++) {
			if (*value == ' ' || *value == '\t') {
				*value = '\0';
				value++;
				break;
			}
			if (*value == '\0') {
				value = NULL;
				break;
			}
		}

		// no value??
		if (value == NULL) {
			log_action(LOG_CRIT, "config error at line %d", line);
			fclose(f);
			if (buf) free(buf);
			return -2;
		}


		// skip white space(s) to value position
		while (*value==' ' || *value=='\t') value++;

		// find end of value and terminate it with '\0'
		// find first occurence of trailing white space
		valend_space = NULL;
		for (valend=value;; valend++) {
			if (*valend == '\0') break;
			if (*valend == '\r' || *valend == '\n') {
				*valend = '\0';
				break;
			}
			if (*valend == ' ' || *valend == '\t') {
				if (!valend_space) valend_space = valend;
			} else {
				valend_space = NULL;
			}
		}

		if (valend_space) *valend_space = '\0';

		found = 0;
		for (option = config_options; option->type != CONFIG_END; option++) {
			if (strcmp(name, option->name) != 0) continue;

			if (parse_value(option, value) < 0) {
				fclose(f);
				log_action(LOG_CRIT, "config[%s]: invalid value", name);
				if (buf) free(buf);
				return -2;
			}

			found = 1;
			break;
		}
		if (found) continue;

		log_action(LOG_CRIT, "Unknown option '%s' at %s line %d", name, filename, line);
		fclose(f);
		if (buf) free(buf);
		return -3;
	}

	fclose(f);
	if (buf) free(buf);

	return 0;
}


/*
 * dump config
*/


void dump_config_var(struct config_option *option, int verbose)
{
	struct option_enum *list;

	switch (option->type) {
	case CONFIG_BOOL:
		CONF_SS(option->name, (*((int *) option->val)) ? "yes" : "no");
		break;

	case CONFIG_INT:
	case CONFIG_PORT:
		CONF_II(option->name, *((int *) option->val));
		break;

	case CONFIG_UINT:
		switch (option->flags & CONF_FLAG_DUMP_MASK) {
		case CONF_FLAG_HEX:
			CONF_HH(option->name, *((uint *) option->val));
			break;

		case CONF_FLAG_OCT:
			CONF_OO(option->name, *((uint *) option->val));
			break;

		case CONF_FLAG_NONE:
		default:
			CONF_UU(option->name, *((uint *) option->val));
			break;
		}
		break;

	case CONFIG_DOUBLE:
		CONF_DO(option->name, *((double *) option->val));
		break;

	case CONFIG_STR:
	case CONFIG_IP4:
//			printf("%-30s '%s'\n", option->name, *((char **) option->val));
		CONF_SS(option->name, *((char **) option->val));
		break;

	case CONFIG_ENUM:
		if (verbose) {
			printf("# %s [ ", option->name);
			printf(IS_FLAG_SET(option->flags, CONF_FLAG_BITMAP) ? "multiple" : "one");
			if (IS_FLAG_SET(option->flags, CONF_FLAG_ARBITRARY)) printf(" integer");
			printf(" ]: {");
			for(list = option->specific; list->name != NULL; list++) {
				printf(" %s", list->name);
			}
			printf(" }\n");
		}
		CONF_HEADER(option->name);
		print_enum_name(option, *((int *) option->val));
		printf("\n");
		break;

	case CONFIG_END:
		break;
	default:
		log_action(LOG_DEBUG, "dump_config(): unknown option type [%d] for %s\n", option->type, option->name);
	}
}

void dump_config(struct config_option config_options[], int verbose)
{
	struct config_option *option;

	printf("# configuration dump for %s %s\n\n", PACKAGE, VERSION);

	for (option = config_options; option->type != CONFIG_END; option++) {
		if (!verbose && IS_FLAG_SET(option->flags, CONF_FLAG_VERBOSE)) continue;
		dump_config_var(option, verbose);
	}
}

int dump_config_by_name(char *name, struct config_option config_options[], int verbose)
{
	struct config_option *option;

	for (option = config_options; option->type != CONFIG_END; option++) {
		if (strcmp(option->name, name) != 0) continue;
		dump_config_var(option, verbose);
		return 0;
	}

	fprintf(stderr, "No such variable [%s]\n", name);
	return -1;
}
