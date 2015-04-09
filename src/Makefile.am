MAINTAINERCLEANFILES	= Makefile.in

AM_CFLAGS		= -fPIC -Werror -funsigned-char -Wno-pointer-sign


AM_CPPFLAGS		= -I$(top_builddir)/include

sbin_PROGRAMS		= boothd

boothd_SOURCES	 	= config.c main.c raft.c ticket.c  transport.c \
			  pacemaker.c handler.c request.c

if BUILD_TIMER_C
boothd_SOURCES += timer.c
endif

boothd_LDFLAGS		= $(OS_DYFLAGS) -L./
boothd_LDADD		= -lplumb -lplumbgpl -lz -lm -lglib-2.0
boothd_CPPFLAGS		= $(GLIB_CFLAGS)

noinst_HEADERS		= booth.h pacemaker.h \
			  config.h log.h raft.h ticket.h transport.h handler.h request.h

lint:
	-splint $(INCLUDES) $(LINT_FLAGS) $(CFLAGS) *.c
