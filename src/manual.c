/*
 * Copyright (C) 2017 Chris Kowalczyk <ckowalczyk@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "manual.h"

#include "transport.h"
#include "ticket.h"
#include "config.h"
#include "log.h"
#include "request.h"


int manual_selection(struct ticket_config *tk,
	struct booth_site *preference, int update_term, cmd_reason_t reason)
{
	if (local->type != SITE)
		return 0;

	tk_log_debug("starting manual selection");
	tk_log_debug("selection caused by %s %s",
				state_to_string(reason),
				reason == OR_AGAIN ? state_to_string(tk->election_reason) : "" );

	// Manual selection is done without any delay, the leader is assigned
	set_leader(tk, local);
	set_state(tk, ST_LEADER);

	// Manual tickets never expire, we don't specify expiration time

	// Make sure that election_end field is empty
	time_reset(&tk->election_end);

	if (is_time_set(&tk->delay_commit) && all_sites_replied(tk)) {
		time_reset(&tk->delay_commit);
		tk_log_debug("reset delay commit as all sites replied");
	}

	save_committed_tkt(tk);

	// Inform others about the new leader
	ticket_broadcast(tk, OP_HEARTBEAT, OP_ACK, RLT_SUCCESS, 0);
	tk->ticket_updated = 0;

	return 0;
}




