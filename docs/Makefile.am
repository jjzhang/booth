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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
MAINTAINERCLEANFILES    = Makefile.in

asciiman	= boothd.8.txt booth-keygen.8.txt geostore.8.txt
doc_DATA	= $(generated_docs)

generated_docs	=
generated_mans	=
ASCIIDOC_ARGS =
A2X_ARGS =

if BUILD_ASCIIDOC_HTML_MAN
generated_docs	+= $(ascii:%.txt=%.html) $(asciiman:%.txt=%.html)
endif
if BUILD_ASCIIDOC
generated_mans	+= $(asciiman:%.8.txt=%.8)
$(generated_mans): $(asciiman)
man8_MANS	= $(generated_mans)
endif

if IS_ASCIIDOC
ASCIIDOC_ARGS += --unsafe --backend=xhtml11
else
ASCIIDOC_ARGS += -b xhtml5
endif

if IS_A2X
A2X_ARGS += -f manpage
else
A2X_ARGS += -b manpage
endif

%.html: %.txt
	$(ASCIIDOC) $(ASCIIDOC_ARGS) $<
%.8: %.8.txt
	$(A2X) $(A2X_ARGS) $<
clean-local:
	-rm -rf $(generated_docs) $(generated_mans)
