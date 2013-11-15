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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _CONFIG_H
#define _CONFIG_H

#include <stdint.h>
#include "booth.h"
#include "config.h"
#include "paxos_lease.h"
#include "transport.h"

#define MAX_NODES	16
#define TICKET_ALLOC	16

#define NO_OWNER (-1)

struct ticket_config {
	boothc_ticket name;

	/* How many seconds to hold it */
	int expiry;
	/* Who has it. */
	int owner; struct booth_node *owner; ??

	/** Timestamp of expiration. */
	time_t expires;

//	pl_handle_t handle; not needed?

	int weight[MAX_NODES];
};

struct booth_config {
    char name[BOOTH_NAME_LEN];
    int node_count;
    int ticket_count;
    transport_layer_t proto;
    uint16_t port;
    struct booth_node node[MAX_NODES];
    struct ticket_config ticket[0];
};

struct booth_config *booth_conf;

int read_config(const char *path);

int check_config(int type);

int find_site_in_config(unsigned char *site, struct booth_node **node);

const char *type_to_string(int type);

static inline struct booth_transport const *transport(void) {
	return booth_transport + booth_conf->proto;
}


#endif /* _CONFIG_H */
