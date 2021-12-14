#	Copyright (C) 2004-2005 Bart³omiej Korupczynski <bartek@klolik.org>
#	
#	This program is free software; you can redistribute it and/or 
#	modify it under the terms of the GNU General Public License 
#	as published by the Free Software Foundation; either 
#	version 2 of the License, or (at your option) any later 
#	version.
#	
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#	
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


sbin_PROGRAMS = smtp-gated
noinst_PROGRAMS = md5-test

smtp_gated_CFLAGS = -I${top_srcdir}/
smtp_gated_LDFLAGS =
smtp_gated_SOURCES = \
	smtp-gated.c smtp-gated.h \
	confvars.c confvars.h \
	conffile.c conffile.h \
	daemon.c daemon.h \
	util.c util.h \
	lookup.c lookup.h \
	scan.c scan.h \
	dump.c dump.h \
	lockfile.c lockfile.h \
	spool.c spool.h \
	md5.c md5.h \
	compat.c compat.h \
	action.c action.h \
	dnsbl.c dnsbl.h \
	ratelimit.c ratelimit.h \
	proxy-helper.h \
	lang.h \
	options.h

if SCANNER_MKSD
smtp_gated_LDADD = libmksd.a
endif

if SCANNER_LIBDSPAM
smtp_gated_LDFLAGS += -ldspam
dspam_test_LDFLAGS = -ldspam
dspam_test_SOURCES = dspam-test.c
noinst_PROGRAMS += dspam-test
endif

if USE_REGEX_PCRE
smtp_gated_SOURCES += regex.c regex.h
smtp_gated_LDFLAGS += -lpcre
regex_test_SOURCES = regex-test.c
regex_test_LDFLAGS = -lpcre
noinst_PROGRAMS += regex-test
endif

if USE_SPF_LIBSPF
smtp_gated_SOURCES += spf.c spf.h
smtp_gated_LDFLAGS += -lspf2
endif

md5_test_SOURCES = md5.c md5.h
md5_test_CFLAGS = -DMD5_TEST


#smtp_gated_LDADD =
#smtp_gated_LDFLAGS = -lresolv


