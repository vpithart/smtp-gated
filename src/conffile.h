/*
 *	conffile.h
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

#ifndef _CONFFILE_H_
#define _CONFFILE_H_

#include <sys/types.h>

#ifndef _CONFFILE_C_
#define EXTERN	extern
#else
#define EXTERN
#endif


/*
 * 	configuration dump macros
*/

#define CONF_HEADER(a)	printf("%-30s ", a);
#define CONF_S(a)	printf("%-30s %s\n", #a, a);
#define CONF_S2(a)	printf("  %-30s: %s\n", #a, a);
#define CONF_SS(a, b)	printf("%-30s %s\n", a, b);
#define CONF_SS2(a, b)	printf("  %-30s: %s\n", a, b);
#define CONF_D(a)	printf("%-30s %d\n", #a, a);
#define CONF_D2(a)	printf("  %-30s: %d\n", #a, a);
// signed int
#define CONF_II(a, b)	printf("%-30s %d\n", a, b);
// unsigned int
#define CONF_UU(a, b)	printf("%-30s %u\n", a, b);
// unsigned int octal
#define CONF_OO(a, b)	printf("%-30s 0%o\n", a, b);
// unsigned int hex
#define CONF_HH(a, b)	printf("%-30s 0x%x\n", a, b);
#define CONF_HH2(a, b)	printf("  %-30s: 0x%x\n", a, b);
#define CONF_HH04(a, b)	printf("%-30s 0x%04x\n", a, b);
#define CONF_HH08(a, b)	printf("%-30s 0x%08x\n", a, b);
// double
#define CONF_DO(a, b)	printf("%-30s %f\n", a, b);


/*
 * 	configuration flags
*/
#define CONF_FLAG_NONE		0x00

// variables dump flags
#define CONF_FLAG_DUMP_MASK	0x0f
// dump as hexadecimal number
#define CONF_FLAG_HEX		0x01
// dump as octal number
#define CONF_FLAG_OCT		0x02
// dump only in verbose mode
#define CONF_FLAG_VERBOSE	0x04

// values validation flags
#define CONF_FLAG_VALID_MASK	0xf0
// allow "-1"
#define CONF_FLAG_MINUS_1	0x10
// allow empty value
#define CONF_FLAG_EMPTY		0x20
// CONFIG_ENUM: allow arbitrary numbers
#define CONF_FLAG_ARBITRARY	0x40
// CONFIG_ENUM: multiple values (a,b,c,...)
#define CONF_FLAG_BITMAP	0x80



typedef enum {
	CONFIG_END = 0,
	// boolean: 0, 1, yes, no, on, off
	CONFIG_BOOL,
	// signed integer: 
	CONFIG_INT, 
	// tcp/udp port:
	CONFIG_PORT,
	// unsigned integer:
	CONFIG_UINT,
	// arbitrary string:
	CONFIG_STR,
	// dotted IP address:
	CONFIG_IP4, 
	// double floating-point number:
	CONFIG_DOUBLE,
	// enumeration (string=>int, string=>int, NULL):
	CONFIG_ENUM
} option_type;


// CONFIG_ENUM type_data:
struct option_enum {
	char *name;
	int value;
};



// default values
typedef union {
	int i;
	uint u;
	char *s;
	double d;
} config_def_val;

// data pointers
typedef union {
	int *i;
	uint *u;
	char *s;
	double *d;
} config_val;


// i.e. { CONFIG_IP4, "bind_address", &config.bind_address, 0, 0x00, { .s = ("0.0.0.0") } },
// option data
struct config_option {
	option_type type;
	char *name;
	void *val;
	size_t size;
	int flags;
	config_def_val def;
	void *specific;		/* option specific data, i.e. enum list pointer */
};



EXTERN int read_config(struct config_option config_options[], char *filename);
EXTERN int config_set_defaults(struct config_option config_options[]);
EXTERN void dump_config_var(struct config_option *option, int verbose);
EXTERN void dump_config(struct config_option config_options[], int verbose);
EXTERN int dump_config_by_name(char *name, struct config_option config_options[], int verbose);


#undef EXTERN

#endif


