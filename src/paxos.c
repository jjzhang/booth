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

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "booth.h"
#include "transport.h"
#include "inline-fn.h"
#include "config.h"
#include "paxos.h"
#include "log.h"


static uint32_t next_ballot_number(struct ticket_config *tk)
{
	uint32_t b;

	/* TODO: getenv() for debugging */

	b = tk->current_state.ballot;
	/* + unique number */
	b += local->bitmask;
	/* + weight */
	b += booth_conf->site_bits * tk->weight[ local->index ];
	return b;
}


int paxos_start_round(struct ticket_config *tk, struct booth_site *new_owner)
{
	struct ticket_paxos_state *tps;

	// TODO needs to be done from cron
	tps = &tk->proposed_state;
	tps->_proposer = local;
	tps->prev_ballot = tk->current_state.ballot;
	tps->ballot = next_ballot_number(tk);
	tps->owner = new_owner;

	ticket_activate_timeout(tk);

	return ticket_broadcast_proposed_state(tk, OP_PREPARING);
}


/** @{ */
/** Message handling functions.
 *
 * Not all use all arguments; but to keep the interface the same,
 * they're all just passed everything we have.
 *
 * A PAXOS round starts by sending out an OP_PREPARING.
 * */


/** Answering OP_PREPARING means sending out OP_PROMISING. */
inline static int answer_PREP(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		int cmd, uint32_t ballot,
		struct booth_site *new_owner)
{
	if (!(local->role & ACCEPTOR))
		return 0;


	/* We have to be careful here.
	 * Getting multiple copies of the same message must not trigger
	 * rejections, but only repeated promises. */
	if (ballot > tk->current_state.ballot) {
		msg->ticket.prev_ballot = htonl(tk->current_state.ballot);
		msg->header.cmd = htonl(OP_PROMISING);

		/* Not allowed:
		 *   tk->current_state.ballot = ballot;
		 *
		 * See above for reasoning.
		 */
		tk->proposed_state.ballot = ballot;

		/* We lose (?) */
		tk->current_state.state = ST_STABLE;
		tk->proposed_state.state = ST_STABLE;

		log_info("PROMISING for ticket \"%s\" (by %s) for %d",
				tk->name, from->addr_string, ballot);
	} else {
		msg->ticket.ballot = htonl(tk->current_state.ballot);
		msg->header.cmd = htonl(OP_REJECTED);

		log_info("REJECTING (prep) for ticket \"%s\" from %s - have %d, wanted %d",
				tk->name, from->addr_string,
				tk->current_state.ballot, ballot);
	}
	init_header_bare(&msg->header);
	return booth_udp_send(from, msg, sizeof(*msg));
}


/** Getting OP_REJECTED means abandoning the current operation. */
inline static int answer_REJ(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		int cmd, uint32_t ballot,
		struct booth_site *new_owner)
{
	log_info("got REJECTED for ticket \"%s\", ballot %d (has %d), from %s",
			tk->name,
			tk->proposed_state.ballot, ballot,
			from->addr_string);

	tk->current_state.ballot = ballot;
	tk->proposed_state.ballot = ballot;

	tk->current_state.state = ST_STABLE;
	return 0;
}


/** After a few OP_PROMISING replies we can send out OP_PROPOSING. */
inline static int answer_PROM(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		int cmd, uint32_t ballot,
		struct booth_site *new_owner)
{
	/* Ignore delayed promises.
	 * They'd only cause packet repetitions anyway. */
	if (tk->proposed_state.state == OP_PREPARING) {
		tk->proposed_state.acknowledges |= from->bitmask;

		log_info("Got PROMISE from %s for \"%s\", now %" PRIx64,
				from->addr_string, tk->name,
				tk->proposed_state.acknowledges);


		/* TODO: only check for count? */
		if (promote_ticket_state(tk)) {
			ticket_activate_timeout(tk);
			return ticket_broadcast_proposed_state(tk, OP_PROPOSING);
		}
	}

	/* Wait for further data */
	return 0;
}


/** Answering OP_PROPOSING means sending out OP_ACCEPTING. */
inline static int answer_PROP(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		int cmd, uint32_t ballot,
		struct booth_site *new_owner)
{
	if (!(local->role & ACCEPTOR))
		return 0;

	/* We have to be careful here.
	 * Getting multiple copies of the same message must not trigger
	 * rejections, but only repeated promises. */
	if (ballot > tk->current_state.ballot &&
			ballot == tk->proposed_state.ballot &&
			ntohl(msg->ticket.prev_ballot) == tk->current_state.ballot) {

		init_ticket_msg(msg, OP_ACCEPTING, RLT_SUCCESS,
				tk, &tk->proposed_state);

		log_info("ACCEPTING for ticket \"%s\" (by %s) for %d - new owner %s",
				tk->name, from->addr_string, ballot,
				ticket_owner_string(new_owner));
	} else {
		msg->ticket.ballot = htonl(tk->current_state.ballot);
		msg->header.cmd = htonl(OP_REJECTED);

		log_info("REJECTING (prop) for ticket \"%s\" from %s - have %d, wanted %d",
				tk->name, from->addr_string,
				tk->current_state.ballot, ballot);
	}
	init_header_bare(&msg->header);
	return booth_udp_send(from, msg, sizeof(*msg));
}


/** After enough OP_ACCEPTING we can do the change, and send an OP_COMMITTED. */
inline static int answer_ACC(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		int cmd, uint32_t ballot,
		struct booth_site *new_owner)
{
	int rv;

	if (tk->proposed_state.state == OP_PROPOSING) {
		tk->proposed_state.acknowledges |= from->bitmask;

		log_info("Got ACCEPTING from %s for \"%s\", now %" PRIx64,
				from->addr_string, tk->name,
				tk->proposed_state.acknowledges);

		/* TODO: only check for count? */
		if (promote_ticket_state(tk)) {
			/* Get previous value for next round */
			tk->proposed_state.prev_ballot =
				tk->current_state.prev_ballot = tk->current_state.ballot;

			tk->current_state.ballot =
				tk->proposed_state.ballot;

			tk->current_state.owner =
				tk->proposed_state.owner;

			tk->current_state.expires = time(NULL) + tk->expiry;

			/* TODO */
			tk->next_cron = time(NULL) +
				tk->current_state.owner == local ?
				tk->expiry / 2 : tk->expiry;

			log_info("Now actively COMMITTED for \"%s\", new owner %s",
					tk->name,
					ticket_owner_string(tk->current_state.owner));

			ticket_write(tk);
			rv = ticket_broadcast_proposed_state(tk, OP_COMMITTED);

			tk->current_state.state =
				tk->proposed_state.state = ST_STABLE;
			return rv;
		}
	}

	/* Wait for further data */
	return 0;


}

/** An OP_COMMITTED gets no answer; just record the new state. */
inline static int answer_COMM(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		int cmd, uint32_t ballot,
		struct booth_site *new_owner)
{
	log_info("COMMITTED for ticket \"%s\", ballot %d, from %s, new owner %s",
			tk->name, ballot,
			from->addr_string, ticket_owner_string(new_owner) );

	tk->proposed_state.prev_ballot =
		tk->current_state.prev_ballot = tk->current_state.ballot;

	tk->proposed_state.ballot =
		tk->current_state.ballot = ballot;

	tk->proposed_state.owner =
		tk->current_state.owner = new_owner;

	tk->current_state.state =
		tk->proposed_state.state = ST_STABLE;

	tk->current_state.expires =
		tk->proposed_state.expires = time(NULL) + tk->expiry;

	/* Nothing to do? */
	tk->next_cron = time(NULL) +
		tk->current_state.owner == local ?
		tk->expiry / 2 : tk->expiry;

	ticket_write(tk);
	/* Send ack? */
	return 0;

}

/** @} */


int paxos_answer(struct boothc_ticket_msg *msg, struct ticket_config *tk,
		struct booth_site *from)
{
	int cmd;
	uint32_t ballot, new_owner;
	struct booth_site *new_owner_p;


	cmd = ntohl(msg->header.cmd);
	ballot = ntohl(msg->ticket.ballot);

	new_owner = ntohl(msg->ticket.owner);
	if (!find_site_by_id(new_owner, &new_owner_p)) {
		log_error("Message with unknown owner %x received", new_owner);
		return -EINVAL;
	}


	/* These are in roughly chronological order.
	 * What the first machine sends is an OP_PREPARING
	 * (see paxos_start_round()), which gets received
	 * (below) from the others ... */
	switch (cmd) {
		case OP_PREPARING:
			return answer_PREP(tk, from, msg, cmd, ballot, new_owner_p);

		case OP_REJECTED:
			return answer_REJ(tk, from, msg, cmd, ballot, new_owner_p);

		case OP_PROMISING:
			return answer_PROM(tk, from, msg, cmd, ballot, new_owner_p);

		case OP_PROPOSING:
			return answer_PROP(tk, from, msg, cmd, ballot, new_owner_p);

		case OP_ACCEPTING:
			return answer_ACC(tk, from, msg, cmd, ballot, new_owner_p);

		case OP_COMMITTED:
			return answer_COMM(tk, from, msg, cmd, ballot, new_owner_p);

		default:
			log_error("unprocessed message, cmd %x", cmd);
			return -EINVAL;
	}
}
