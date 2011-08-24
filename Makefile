INIT_DIR=/etc/init.d
RSC_DIR=/usr/lib/ocf/resource.d/pacemaker
BOOTH_SITE=./script/ocf/booth-site
BOOTH_ARBITRATOR=./script/lsb/booth-arbitrator

INSTALL=$(shell which install)

all:
	${MAKE} -C ./src
	
install:
	${MAKE} -C ./src install
	mkdir -p $(DESTDIR)/$(RSC_DIR)
	mkdir -p $(DESTDIR)/$(INIT_DIR)
	$(INSTALL) -c -m 755 $(BOOTH_SITE) $(DESTDIR)/$(RSC_DIR)	
	$(INSTALL) -c -m 755 $(BOOTH_ARBITRATOR) $(DESTDIR)/$(INIT_DIR)	

clean:
	${MAKE} -C ./src clean
