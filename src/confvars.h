/*
 * 	confvars.h
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

#if !defined _CONFVARS_H_ || defined _CONFVARS_C
#define _CONFVARS_H_

/*
 * _CONFVARS_C:
 *	1: variables definitions
 *	2: variables list (struct config_options)
 *	3: variables init function
*/

#ifndef _CONFVARS_C
	#include <stdlib.h>
	#include <sys/types.h>
	#include "conffile.h"
#endif

#ifndef _CONFVARS_C
	#define INIT(x)
	#define EXTERN extern
#else
	#define INIT(x)	= (x)
	#define EXTERN
#endif

#if _CONFVARS_C == 1
	#include "lang.h"
#endif



#if _CONFVARS_C == 2
	/* options list section */
	// string types
	#define CONF_OPT_STR(a, v)		{ CONFIG_STR, #a, &config.a, 0, CONF_FLAG_NONE, { .s = (v) } },
	#define CONF_OPT_STR_EMPTY(a, v)	{ CONFIG_STR, #a, &config.a, 0, CONF_FLAG_EMPTY, { .s = (v) } },
	#define CONF_OPT_STR_VERBOSE(a, v)	{ CONFIG_STR, #a, &config.a, 0, CONF_FLAG_VERBOSE, { .s = (v) } },
	#define CONF_OPT_IP4(a, v)		{ CONFIG_IP4, #a, &config.a, 0, CONF_FLAG_NONE, { .s = (v) } },
	#define CONF_OPT_IP4_EMPTY(a, v)	{ CONFIG_IP4, #a, &config.a, 0, CONF_FLAG_EMPTY, { .s = (v) } },
	
	// integer types
	#define CONF_OPT_INT(a, v)		{ CONFIG_INT, #a, &config.a, 0, CONF_FLAG_NONE, { .i = (v) } },
	#define CONF_OPT_BOOL(a, v)		{ CONFIG_BOOL, #a, &config.a, 0, CONF_FLAG_NONE, { .i = (v) } },
	#define CONF_OPT_PORT(a, v)		{ CONFIG_PORT, #a, &config.a, 0, CONF_FLAG_NONE, { .i = (v) } },
	#define CONF_FOPT_PORT(a, v, f)		{ CONFIG_PORT, #a, &config.a, 0, f, { .i = (v) } },
	
	// unsigned integer types
	#define CONF_OPT_UINT(a, v)		{ CONFIG_UINT, #a, &config.a, 0, CONF_FLAG_NONE, { .u = (v) } },
	#define CONF_OPT_HEX(a, v)		{ CONFIG_UINT, #a, &config.a, 0, CONF_FLAG_HEX, { .u = (v) } },
	#define CONF_OPT_OCT(a, v)		{ CONFIG_UINT, #a, &config.a, 0, CONF_FLAG_OCT, { .u = (v) } },
	
	// floating types
	#define CONF_OPT_DOUBLE(a, v)		{ CONFIG_DOUBLE, #a, &config.a, 0, CONF_FLAG_NONE, { .d = (v) } },

	// enumeration types
	#define CONF_OPT_ENUM(o, a, v, l)	{ CONFIG_ENUM, #a, &config.a, 0, o, { .i = (v) }, l },
#elif _CONFVARS_C == 3
	/* initialisation section */
	#define CONF_OPT_STR(a, v)		vars->a = strdup(v);
	#define CONF_OPT_STR_EMPTY(a, v)	CONF_OPT_STR(a, v)
	#define CONF_OPT_STR_VERBOSE(a, v)	CONF_OPT_STR(a, v)
	#define CONF_OPT_IP4(a, v)		CONF_OPT_STR(a, v)
	#define CONF_OPT_IP4_EMPTY(a, v)		CONF_OPT_STR(a, v)

	#define CONF_OPT_INT(a, v)		vars->a = (v);
	#define CONF_OPT_BOOL(a, v)		CONF_OPT_INT(a, v)
	#define CONF_OPT_PORT(a, v)		CONF_OPT_INT(a, v)
	#define CONF_FOPT_PORT(a, v)		CONF_FOPT_PORT(a, v)

	#define CONF_OPT_UINT(a, v)		CONF_OPT_INT(a, v)
	#define CONF_OPT_HEX(a, v)		CONF_OPT_INT(a, v)
	#define CONF_OPT_OCT(a, v)		CONF_OPT_INT(a, v)

	#define CONF_OPT_DOUBLE(a, v)		CONF_OPT_INT(a, v)

	#define CONF_OPT_ENUM(o, a, v, l)	CONF_OPT_INT(a, v)
#else
	/* struct declaration section */
	// string types
	#define CONF_OPT_STR(a, v)		char *a;
	#define CONF_OPT_STR_EMPTY(a, v)	CONF_OPT_STR(a, v)
	#define CONF_OPT_STR_VERBOSE(a, v)	CONF_OPT_STR(a, v)
	#define CONF_OPT_IP4(a, v)		CONF_OPT_STR(a, v)
	#define CONF_OPT_IP4_EMPTY(a, v)		CONF_OPT_STR(a, v)
	
	// integer types
	#define CONF_OPT_INT(a, v)		int a;
	#define CONF_OPT_BOOL(a, v)		CONF_OPT_INT(a, v)
	#define CONF_OPT_PORT(a, v)		CONF_OPT_INT(a, v)
	#define CONF_FOPT_PORT(a, v, f)		CONF_OPT_INT(a, v)
	
	// unsigned integer types
	#define CONF_OPT_UINT(a, v)		uint a;
	#define CONF_OPT_HEX(a, v)		CONF_OPT_UINT(a, v)
	#define CONF_OPT_OCT(a, v)		CONF_OPT_UINT(a, v)
	
	// floating types
	#define CONF_OPT_DOUBLE(a, v)		double a;

	// enumeration types
	#define CONF_OPT_ENUM(o, a, v, l)	int a;
#endif

#if _CONFVARS_C == 1
#endif

#if !defined(_CONFVARS_C) || _CONFVARS_C == 1
struct config_vars {
	#include "options.h"
};
#else
	#include "options.h"
#endif

#ifndef _CONFVARS_C
EXTERN struct config_option *config_options;
EXTERN void confvars_init(struct config_vars *vars);
EXTERN struct config_vars config;
#endif




// undefine any local MACROS
#undef EXTERN
#undef INIT

#undef CONF_OPT_STR
#undef CONF_OPT_STR_EMPTY
#undef CONF_OPT_STR_VERBOSE
#undef CONF_OPT_IP4
#undef CONF_OPT_IP4_EMPTY

#undef CONF_OPT_INT
#undef CONF_OPT_BOOL
#undef CONF_OPT_PORT
#undef CONF_FOPT_PORT

#undef CONF_OPT_UINT
#undef CONF_OPT_HEX
#undef CONF_OPT_OCT

#undef CONF_OPT_DOUBLE
#undef CONF_OPT_ENUM


// end
#endif

