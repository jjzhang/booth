BIN_TARGET = booth

HEADER_TARGET = booth.h config.h list.h log.h pacemaker.h paxos.h paxos_lease.h ticket.h timer.h transport.h

BIN_SOURCE = config.c log.c main.c pacemaker.c paxos.c paxos_lease.c ticket.c timer.c transport.c 

CFLAGS += -D_GNU_SOURCE -g \
	-Wall \
	-Wformat \
	-Wformat-security \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wpointer-arith \
	-Wextra -Wshadow \
	-Wcast-align \
	-Wwrite-strings \
	-Waggregate-return \
	-Wstrict-prototypes \
	-Winline \
	-Wredundant-decls \
	-Wno-sign-compare \
	-Wp,-D_FORTIFY_SOURCE=2 \
	-fexceptions \
	-fasynchronous-unwind-tables \
	-fdiagnostics-show-option

BIN_LDFLAGS = -lpthread

$(BIN_TARGET): $(BIN_SOURCE)
	$(CC) $(CFLAGS) $(BIN_LDFLAGS) $(BIN_SOURCE) -o $@

clean:
	rm -f $(BIN_TARGET)
	rm -f cscope.*

INSTALL=$(shell which install)

BIN_DIR=/usr/sbin
HEADER_DIR=/usr/include

.PHONY: install
install: $(BIN_TARGET)
	mkdir -p $(DESTDIR)/$(BIN_DIR)
	mkdir -p $(DESTDIR)/$(HEADER_DIR)
	$(INSTALL) -c -m 755 $(BIN_TARGET) $(DESTDIR)/$(BIN_DIR)
	$(INSTALL) -c -m 644 $(HEADER_TARGET) $(DESTDIR)/$(HEADER_DIR)

.PHONY: cscope
cscope:
	rm -f cscope.*
	echo "-k" >> cscope.files
	find . -name '*.[ch]' >> cscope.files
	cscope -b

