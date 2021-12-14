/*
 *	scan.h
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

#ifndef _SCAN_H_
#define _SCAN_H_

#ifndef _SCAN_C_
#define EXTERN extern
#else
#define EXTERN
#endif


/*
 * upcoming generic results for all scanners:
*/
#if 0
typedef enum {
	SCAN_INVALID = 0,	/* should never happen; bug */
	SCAN_FAILED,		/* scanner failure; reject if !ignore_errors */
	SCAN_TIMEOUT,		/* scanner timeout; same as SCAN_FAILED? ignore_timeout? */
	SCAN_SKIPPED,		/* scanner skipped due to oversize message, cpu overload, etc */
	SCAN_PASS,			/* message clean */
	SCAN_REJECT			/* message malicious (virus, spam, dnsbl-ed, spf fail) */
} scan_result_t;

// printf("%s:%s, info=%s", scanner_name, scanner_result_str(res), scanner_comment)
// ANTIVIR:REJECT, name=Eicar
// SPAMASSASSIN:REJECT, score=5.0
// SPAMASSASSIN:SKIPPED, load=2.0, size=1000193
// SPF:REJECT, result=neutral
// DNSBL:REJECT, domain=second.dnsbl.example.com
#endif

/*
 *	scanning results
*/
typedef enum {
	SCAN_UNKNOWN = 0,
	SCAN_OK, SCAN_VIRUS,
	SCAN_FAILED, SCAN_TIMEOUT,
	SCAN_SKIPPED
} av_result;
typedef enum { SPAM_UNKNOWN = 0,
	/* return SPAM_OK to set SPAM_YES/SPAM_NO depending on spamscore (in spool.c) */
	SPAM_OK,
	SPAM_NO, SPAM_YES,
	SPAM_FAILED, SPAM_TIMEOUT,
	SPAM_SKIPPED
} spam_result;

typedef enum { SCAN_PASS = 0, SCAN_TAKEOVER } scan_result;

typedef enum {
	AV_NONE = 0, AV_SCRIPT, AV_PIPE,
	AV_CLAMD, AV_MKSD, AV_DRWEB,
	/* <END OF AV-ENUM> */
	AV_END_LIST
} antivirus_type_enum;

typedef enum {
	AS_NONE = 0, AS_SCRIPT, AS_PIPE,
	AS_SPAMASSASSIN,
	AS_LIBDSPAM,
	/* <END OF AS-ENUM> */
	AS_END_LIST
} antispam_type_enum;


/*
 *	configuration strings
*/
#ifndef _SCAN_C_
EXTERN struct option_enum antispam_type_list[];
EXTERN struct option_enum antivirus_type_list[];
#endif

/*
 *	scanners
*/

EXTERN av_result av_scanner(char *filename, char **result);
EXTERN spam_result spam_scanner(char *filename, double *score);



#undef EXTERN

#endif


