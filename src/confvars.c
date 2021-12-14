/*
 * 	confvars.c
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#define SYSLOG_NAMES
#include <syslog.h>
#include "conffile.h"
#include "lang.h"
#include "smtp-gated.h"
#include "util.h"
#include "scan.h"
#include "lockfile.h"
#include "spool.h"
#include "dump.h"
#include "spf.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif


struct option_enum boolean_list[] = {
	{ "yes", 1 },
	{ "true", 1 },
	{ "on", 1 },
	{ "1", 1 },
	{ "off", 0 },
	{ "no", 0 },
	{ "false", 0 },
	{ "0", 0 },
	{ NULL}
};


#define _CONFVARS_C 1
#include "confvars.h"

struct config_vars config;

#undef _CONFVARS_C
#define _CONFVARS_C 2

struct config_option opt[] = {
	#include "confvars.h"
	{ CONFIG_END }
};

struct config_option *config_options = opt;

#undef _CONFVARS_C
#define _CONFVARS_C 3

void confvars_init(struct config_vars *vars)
{
	#include "confvars.h"
}
