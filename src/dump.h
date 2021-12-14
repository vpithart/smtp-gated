/*
 *	dump.h
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


#ifndef _DUMP_H_
#define _DUMP_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#include <syslog.h>
#include <signal.h>

#ifndef _DUMP_C_
#define EXTERN extern
#else
#define EXTERN
#endif


enum {
	DUMPFILE_TYPE_HUMAN = 0x00,
	DUMPFILE_TYPE_FLAT	= 0x02,
	DUMPFILE_TYPE_SLOTS = 0x04
};


#ifndef _DUMP_C_
EXTERN volatile sig_atomic_t timedout;
EXTERN int i_am_a_child;
#endif

EXTERN struct option_enum statefile_type_list[];

EXTERN void log_stats();
EXTERN void dump_state();
EXTERN void dump_ver(int verbose);


#undef EXTERN

#endif


