# Copyright (C) 2012, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

MAINTAINERCLEANFILES = Makefile.in

INCLUDES                = -I/usr/include/pacemaker \
                        -I/usr/include/heartbeat \
                        -I/usr/include/libxml2 \
                        -I$(srcdir)

if RESOURCE_MONITOR
sbin_PROGRAMS          = booth_resource_monitord

# BUILD

booth_resource_monitord_SOURCES        = booth_resource_monitord.c
booth_resource_monitord_LDADD          = -lcrmcommon \
                                         -lcrmcluster \
                                         -lpe_status \
                                         -lcib
booth_resource_monitord_CPPFLAGS       = $(GLIB_CFLAGS)
endif


AM_CFLAGS               = -Wall -Werror
