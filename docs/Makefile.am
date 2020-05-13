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

EXTRA_DIST	= boothd.8.txt booth-keygen.8.txt fsm-full.dot fsm-netfail.dot fsm-normal.dot geostore.8.txt

asciiman	= boothd.8.txt booth-keygen.8.txt geostore.8.txt
doc_DATA	= $(generated_docs)

generated_docs	=
generated_mans	=
HTML_GENERATOR =
MANPAGE_GENERATOR =

if BUILD_ASCIIDOC_HTML_MAN
generated_docs	+= $(ascii:%.txt=%.html) $(asciiman:%.txt=%.html)
endif
if BUILD_ASCIIDOC
generated_mans	+= $(asciiman:%.8.txt=%.8)
$(generated_mans): $(asciiman)
man8_MANS	= $(generated_mans)
endif

if IS_ASCIIDOC
HTML_GENERATOR += $(ASCIIDOC) --unsafe --backend=xhtml11 --destination-dir=$(abs_builddir)/
else
HTML_GENERATOR += $(ASCIIDOCTOR) -b xhtml5 --destination-dir=$(abs_builddir)/
endif

if IS_A2X
MANPAGE_GENERATOR += $(A2X) -f manpage --destination-dir=$(abs_builddir)/
else
MANPAGE_GENERATOR += $(ASCIIDOCTOR) -b manpage --destination-dir=$(abs_builddir)/
endif

%.html: %.txt
	$(HTML_GENERATOR) $<
%.8: %.8.txt
	$(MANPAGE_GENERATOR) $<
clean-local:
	-rm -rf $(generated_docs) $(generated_mans)
