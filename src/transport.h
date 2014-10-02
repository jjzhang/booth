/* 
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013 Philipp Marek <philipp.marek@linbit.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _TRANSPORT_H
#define _TRANSPORT_H

#include "booth.h"

typedef enum {
	TCP = 1,
	UDP,
	SCTP,
	TRANSPORT_ENTRIES,
} transport_layer_t;

typedef enum {
	ARBITRATOR = 0x50,
	SITE,
	CLIENT,
	DAEMON,
	STATUS,
} action_t;

struct booth_transport {
	const char *name;
	int (*init) (void *);
	int (*open) (struct booth_site *);
	int (*send) (struct booth_site *, void *, int);
	int (*recv) (struct booth_site *, void *, int);
	int (*broadcast) (void *, int);
	int (*close) (struct booth_site *);
	int (*exit) (void);
};

extern const struct booth_transport booth_transport[TRANSPORT_ENTRIES];
int find_myself(struct booth_site **me, int fuzzy_allowed);

int check_boothc_header(struct boothc_header *data, int len_incl_data);

int setup_tcp_listener(int test_only);
int booth_udp_send(struct booth_site *to, void *buf, int len);

int booth_tcp_open(struct booth_site *to);
int booth_tcp_send(struct booth_site *to, void *buf, int len);

inline static void * node_to_addr_pointer(struct booth_site *node) {
	switch (node->family) {
	case AF_INET:  return &node->sa4.sin_addr;
	case AF_INET6: return &node->sa6.sin6_addr;
	}
	return NULL;
}

extern const struct booth_transport *local_transport;

int send_header_only(int fd, struct boothc_header *hdr);
int send_header_plus(int fd, struct boothc_header *hdr, void *data, int len);
int send_ticket_msg(int fd, struct boothc_ticket_msg *msg);


#endif /* _TRANSPORT_H */
