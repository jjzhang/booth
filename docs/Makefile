


all:	boothd.8 boothd.html


boothd.8: boothd.8.txt
	a2x --doctype manpage --format manpage --verbose $<

boothd.html: boothd.8.txt
	a2x --doctype manpage --format xhtml --verbose $<
