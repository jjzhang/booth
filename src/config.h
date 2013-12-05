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
#include "paxos_lease.h"
#include "transport.h"


/** @{ */
/** Definitions for in-RAM data. */

#define MAX_NODES	16
#define TICKET_ALLOC	16


struct ticket_paxos_state {
	/** See booth_site:site_id. */
	uint32_t proposer;
	struct booth_site *_proposer;

	/** See booth_site:site_id. */
	struct booth_site *owner;

	/** Timestamp of expiration. */
	time_t expires;

	/** State. */
	cmd_request_t state;

	/** Current ballot number. Might be < prev_ballot if overflown. */
	uint32_t ballot;
	/** Previous ballot. */
	uint32_t prev_ballot;

	/** Bitmap of sites that acknowledge that state. */
	uint64_t acknowledges;
};


struct ticket_config {
	boothc_ticket name;

	/** How many seconds until expiration. */
	int expiry;

	/** Network related timeouts. */
	int timeout;


//	pl_handle_t handle; not needed?

	int weight[MAX_NODES];

	/* Only used on the owner, */
	struct timerlist *refresh_ticket;
	time_t next_cron;

	struct ticket_paxos_state current_state;
	struct ticket_paxos_state proposed_state;
};

struct booth_config {
    char name[BOOTH_NAME_LEN];

    transport_layer_t proto;
    uint16_t port;

	/** Stores the OR of the individual host bitmasks. */
	uint32_t site_bits;

    int node_count;
    struct booth_site node[MAX_NODES];

    int ticket_count;
    int ticket_allocated;
    struct ticket_config *ticket;
};


extern struct booth_config *booth_conf;


int read_config(const char *path);

int check_config(int type);

int find_site_by_name(unsigned char *site, struct booth_site **node);
int find_site_by_id(uint32_t site_id, struct booth_site **node);

const char *type_to_string(int type);


#define STATE_STRING(s_) ({ union { cmd_request_t s; char c[5]; } d; d.s = htonl(s_); d.c[4] = 0; d.c; })


#endif /* _CONFIG_H */
