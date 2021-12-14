/*
 * 	lang-pl.h
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

/* polish messages */
#define MSG_VIRUS_FOUND				"Malware found/Odnaleziono wirusa"
#define MSG_VIRUS_NO_MORE			"Znaleziono wirusa, idz sobie"
#define MSG_VIRUS_LOCKED			"Zostales zablokowany ze wzgledu na rozsylanie wirusow lub SPAM-u"
#define MSG_SPAM_FOUND				"Wiadomosc zostala rozpoznana jako SPAM i zostala zablokowana"
#define MSG_SCANNER_FAILED			"Awaria skanera antywirusowego"
#define MSG_MALFORMED_IP			"Nieprawidlowy adres IP"
#define MSG_CANNOT_CONNECT			"Nie mozna polaczyc sie z serwerem"
#define MSG_SPOOL_PROBLEM			"Problem z nazwa pliku tymczasowego"
#define MSG_SPOOL_OPEN_FAIL			"Problem z plikiem tymczasowym"
#define MSG_PIPELINE_FULL			"Przepelniona kolejka rozkazow"
#define MSG_LOOKUP_FAILED			"Lookup failed"
#define MSG_LOOKUP_TIMEOUT			"Lookup timeout"
#define MSG_LOOKUP_MISMATCH			"Lookup format mismatch"
#define MSG_LOOKUP_NOMEM			"Lookup out of memory"
#define MSG_LOOKUP_NOTFOUND			"Lookup destination not found"
#define MSG_CONNECT_TIMEOUT			"Uplynal czas oczekiwania na polaczenie"
#define MSG_CONNECT_FAILED			"Connection failed"
#define MSG_UNKNOWN_VIRUS			"uknown/nieznany"
#define MSG_SESSION_TIMEOUT			"SMTP session timeout. Closing connection"
#define MSG_SIGN_OFF				"Signing off."
#define MSG_HELLO				"SMTP Proxy, hello"
#define MSG_PROTO_ERROR				"Protocol error"
#define MSG_TRANSACTION_FAILED			"Transaction failed"
#define MSG_UNIMPL_COMMAND			"Command not implemented"
#define MSG_TEMP_UNAVAIL			"Usluga chwilowo niedostepna"
#define MSG_MAX_REACHED				"Zbyt wiele polaczen, sprobuj pozniej"
#define MSG_MAX_PER_HOST			"Zbyt wiele polaczen z Twojego adresu, sprobuj pozniej"
#define MSG_MAX_PER_IDENT			"Zbyt wiele polaczen z Twojego identa, sprobuj pozniej"
#define MSG_SYSTEM_LOAD				"Zbyt duze obciazenie systemu, sprobuj pozniej"
#define MSG_NOMEM					"Za malo pamieci"
#define MSG_UNKNOWN_SCANNER			"Nieznany typ skanera"
#define MSG_UNKNOWN_LOOKUP			"Nieznany tryb"
#define MSG_AUTH_REQUIRED			"Wysylka bez autoryzacji zabroniona"
#define MSG_LOOP_AVOIDANCE			"TPROXY loop avoidance"
#define MSG_DNSBL_REJECT			"Polaczenie odrzucone przez DNSBL"
#define MSG_SPF_REJECT				"Polaczenie odrzucone przez SPF, wlacz autoryzacje poczty wychodzacej (SMTP)"
#define MSG_SIZE_LIMIT				"Przekroczony limit rozmiaru wiadomosci"
#define MSG_FIXED_XCLIENT_FAIL			"Blad polaczenia z MTA (XCLIENT)"
#define MSG_REGEX_HELO				"Zabronione HELO/EHLO"
#define MSG_REGEX_MAIL_FROM			"Zabronione MAIL FROM"
#define MSG_REGEX_RCPT_TO			"Zabronione RCPT TO"
#define MSG_RATE_REJECT				"Odrzucone z powodu przekroczenia limitow"
#define MSG_RATELIMIT_ERROR			"Ratelimiter error"
#define MSG_RATELIMIT_MESSAGES			"Przekroczony okresowy limit wiadomosci"
#define MSG_RATELIMIT_RCPTTO			"Przekroczony okresowy limit odbiorcow"
#define MSG_RATELIMIT_RCPTTO_REJECTS		"Przekroczony okresowy limit odrzuconych odbiorcow"
#define MSG_RATELIMIT_HELO			"Przekroczony okresowy limit powitan HELO/EHLO SMTP"
#define MSG_RATELIMIT_MAILFROM			"Przekroczony okresowy limit roznych adresow nadawcy"
#define MSG_RATELIMIT_MAILFROM_REJECTS		"Przekroczony okresowy limit odrzuconych adresow nadawcy"
#define MSG_RATELIMIT_DST			"Przekroczony okresowy limit roznych serwerow SMTP"
#define MSG_EARLYTALKER				"Nastepnym razem poczekaj na powitanie"

