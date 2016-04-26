MAINTAINERCLEANFILES	= Makefile.in

AM_CFLAGS		= -fPIC -Werror -funsigned-char -Wno-pointer-sign


AM_CPPFLAGS		= -I$(top_builddir)/include

sbin_PROGRAMS		= boothd

boothd_SOURCES	 	= config.c main.c raft.c ticket.c  transport.c \
			  pacemaker.c handler.c request.c attr.c

noinst_HEADERS		= booth.h pacemaker.h \
			  config.h log.h raft.h ticket.h transport.h handler.h request.h attr.h

if BUILD_TIMER_C
boothd_SOURCES += timer.c
endif

if BUILD_AUTH_C
boothd_SOURCES += auth.c
endif

boothd_LDFLAGS		= $(OS_DYFLAGS) -L./
boothd_LDADD		= -lplumb -lplumbgpl -lm $(GLIB_LIBS) $(ZLIB_LIBS)
boothd_CFLAGS		= $(GLIB_CFLAGS)

if !LOGGING_LIBQB
boothd_LDADD		+= -lplumb
else
boothd_LDADD		+= $(LIBQB_LIBS)
boothd_SOURCES		+= alt/logging_libqb.c
noinst_HEADERS		+= alt/logging_libqb.h
endif

lint:
	-splint $(INCLUDES) $(LINT_FLAGS) $(CFLAGS) *.c
