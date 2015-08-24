#
# docs: booth manual pages
#
# Copyright (C) 2014 Dejan Muhamedagic
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
MAINTAINERCLEANFILES    = Makefile.in

asciiman	= boothd.8.txt booth-keygen.8.txt geostore.8.txt
doc_DATA	= $(generated_docs)

generated_docs	=
generated_mans	=

if BUILD_ASCIIDOC
generated_docs	+= $(ascii:%.txt=%.html) $(asciiman:%.txt=%.html)
generated_mans	+= $(asciiman:%.8.txt=%.8)
$(generated_mans): $(asciiman)
man8_MANS	= $(generated_mans)
endif

%.html: %.txt
	$(ASCIIDOC) --unsafe --backend=xhtml11 $<
%.8: %.8.txt
	a2x -f manpage $<
clean-local:
	-rm -rf $(generated_docs) $(generated_mans)
