


all:	boothd.8 boothd.html boothd.xml


boothd.8: boothd.8.txt
	a2x --doctype manpage --format manpage --verbose $<

boothd.html: boothd.8.txt
	a2x --doctype manpage --format xhtml --verbose $<

boothd.xml: boothd.8.txt
	a2x --doctype manpage --format docbook --verbose $<
