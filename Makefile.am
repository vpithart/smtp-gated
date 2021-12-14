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


EXTRA_DIST = configure smtp-gated.spec smtp-gated.spec.in bootstrap.sh README.PL debian .released
SUBDIRS = src doc contrib lib lang tests

#test:
#	cd tests && $(MAKE) $(AM_MAKEFLAGS) test

#test:
#	cd tests && ./run-tests.pl

test:
	$(MAKE) -C tests test

