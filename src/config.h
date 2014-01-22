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
#include "transport.h"


/** @{ */
/** Definitions for in-RAM data. */

#define MAX_NODES	16
#define TICKET_ALLOC	16


#define RETRIES  10


struct ticket_config {
	/** \name Configuration items.
	 * @{ */
	/** Name of ticket. */
	boothc_ticket name;

	/** How many seconds until expiration. */
	int expiry;

	/** Network related timeouts. */
	int timeout;

	/** If >0, time to wait for a site to get fenced.
	 * The ticket may be acquired after that timespan by
	 * another site. */
	int acquire_after;


	/** Node weights. */
	int weight[MAX_NODES];
	/** @} */


	/** \name Runtime values.
	 * @{ */
	/** Current state. */
	cmd_request_t state;

	/** When something has to be done */
	struct timeval next_cron;

	/** Current owner of ticket. */
	struct booth_site *owner;

	/** Timestamp of expiration. */
	time_t expires;

	/** Last ballot number that was agreed on. */
	uint32_t last_ack_ballot;
	/** @} */


	/** \name Needed while proposals are being done.
	 * @{ */
	/** Who tries to change the current status. */
	struct booth_site *proposer;

	/** Current owner of ticket. */
	struct booth_site *proposed_owner;

	/** New/current ballot number.
	 * Might be < prev_ballot if overflown.
	 * This only every goes "up" (logically). */
	uint32_t new_ballot;

	/** Bitmap of sites that acknowledge that state. */
	uint64_t proposal_acknowledges;

	/** When an incompletely acknowledged proposal gets done.
	 * If all peers agree, that happens sooner.
	 * See switch_state_to(). */
	struct timeval proposal_switch;

	/** Timestamp of proposal expiration. */
	time_t proposal_expires;

	/** Number of send retries left.
	 * Used on the new owner.
	 * Starts at 0, counts up. */
	int retry_number;
	/** @} */
};


struct booth_config {
    char name[BOOTH_NAME_LEN];

    transport_layer_t proto;
    uint16_t port;

    /** Stores the OR of the individual host bitmasks. */
    uint64_t site_bits;

    int site_count;
    struct booth_site site[MAX_NODES];

    int ticket_count;
    int ticket_allocated;
    struct ticket_config *ticket;
};


extern struct booth_config *booth_conf;


int read_config(const char *path);

int check_config(int type);

int find_site_by_name(unsigned char *site, struct booth_site **node, int any_type);
int find_site_by_id(uint32_t site_id, struct booth_site **node);

const char *type_to_string(int type);


#define STATE_STRING(s_) ({ union { cmd_request_t s; char c[5]; } d; d.s = htonl(s_); d.c[4] = 0; d.c; })


#endif /* _CONFIG_H */
