/*
 * 	daemon.h
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


#ifndef _DAEMON_H_
#define _DAEMON_H_

#ifndef _DAEMON_C_
#define EXTERN extern
#else
#define EXTERN
#endif

#define DAEMONIZE_SET_EUID_ONLY		0x01



EXTERN int pidfile_create(char *pidfile);
EXTERN int pidfile_remove(char *pidfile);
EXTERN int pidfile_signal(int signum, char *pidfile);

EXTERN int daemonize(char *log_ident, int log_facility, int process_priority,
		char *chroot_path, char *pidfile, char *user, char *group, int flags);

EXTERN int drop_privileges();
EXTERN int elevate_privileges();
EXTERN int lower_privileges();

#undef EXTERN

#endif

