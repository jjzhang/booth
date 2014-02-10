/*
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013-2014 Philipp Marek <philipp.marek@linbit.com>
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

	b = tk->new_ballot;
	/* + unique number */
	b += local->bitmask;
	/* + weight */
	b += booth_conf->site_bits * tk->weight[ local->index ];
	return b;
}


static inline void set_proposal_in_ticket(struct ticket_config *tk,
		struct booth_site *from,
		uint32_t ballot, struct booth_site *new_owner)
{
	tk->proposer = from;
	tk->new_ballot = ballot;
	tk->proposed_owner = new_owner;
	tk->proposal_expires = 0; // TODO - needed?
	tk->proposal_acknowledges = from->bitmask | local->bitmask;

	/* We lose (?) */
	tk->state = ST_STABLE;
}


int should_switch_state_p(struct ticket_config *tk)
{
	if (all_agree(tk)) {
		log_debug("all agree");
		return 1;
	}

	if (majority_agree(tk)) {
		/* Time passed, and more than half agree. */
		if (timeval_in_past(tk->proposal_switch)) {
			log_debug("majority, and enough time passed");
			return 2;
		}

		if (!tk->proposal_switch.tv_sec) {
			log_debug("majority, wait half a second");
			/* Wait half a second before doing the state change. */
			ticket_next_cron_in(tk, 0.5);
			tk->proposal_switch = tk->next_cron;
		}
	}

	return 0;
}


static int retries_exceeded(struct ticket_config *tk)
{
	int ret;

	if (tk->retry_number >= tk->retries) {
		log_info("ABORT %s for ticket \"%s\" - "
				"not enough answers after %d retries (of %d)",
				tk->state == OP_PREPARING ? "prepare" : "propose",
				tk->name, tk->retry_number, tk->retries);
		abort_proposal(tk);


		/* Keep on trying to refresh. */
		if (owner_and_valid(tk))
			tk->state = ST_STABLE;

		ret = EBUSY;
	} else {
		/* We ask others for a change; retry to get
		 * consensus.
		 * But don't ask again immediately after a
		 * query, give the peers time to answer. */
		if (timeval_in_past(tk->proposal_switch)) {
			ticket_broadcast_proposed_state(tk, tk->state);
		}
		ret = 0;
	}


	disown_if_expired(tk);
	ticket_activate_timeout(tk);

	return ret;
}


static inline void change_ticket_owner(struct ticket_config *tk,
		uint32_t ballot,
		struct booth_site *new_owner)
{
	/* set "previous" value for next round */
	tk->last_ack_ballot =
		tk->new_ballot = ballot;

	tk->owner = new_owner;
	tk->expires = time(NULL) + tk->expiry;
	tk->proposer = NULL;

	tk->state = ST_STABLE;

	set_ticket_wakeup(tk);
	log_info("Now actively COMMITTED for \"%s\": new owner %s, ballot %d",
			tk->name,
			ticket_owner_string(tk->owner),
			ballot);


	ticket_write(tk);
}


void abort_proposal(struct ticket_config *tk)
{
	log_info("ABORTing proposal.");
	tk->proposer = NULL;
	tk->proposed_owner = tk->owner;
	tk->retry_number = 0;
	/* Ask others (repeatedly) until we know the new owner. */
	tk->state = ST_INIT;
}


int PROPOSE_to_COMMIT(struct ticket_config *tk)
{
	int rv;

	if (should_switch_state_p(tk)) {
		change_ticket_owner(tk, tk->new_ballot, tk->proposed_owner);

		rv = ticket_broadcast_proposed_state(tk, OP_COMMITTED);
		tk->state = ST_STABLE;
		return rv;
	}

	return retries_exceeded(tk);
}


int PREPARE_to_PROPOSE(struct ticket_config *tk)
{
	if (should_switch_state_p(tk)) {
		return ticket_broadcast_proposed_state(tk, OP_PROPOSING);
	}

	return retries_exceeded(tk);
}



/** \defgroup msghdl Message handling functions.
 *
 * Not all use all arguments; but to keep the interface the same,
 * they're all just passed everything we have.
 *
 * See also enum \ref cmd_request_t.
 * @{ */


/** Start a PAXOS round, by sending out an OP_PREPARING. */
int paxos_start_round(struct ticket_config *tk, struct booth_site *new_owner)
{
	if (tk->state != ST_STABLE)
		return RLT_BUSY;

	/* This may not be called repeatedly from cron,
	 * because the ballot number would simply
	 * get counted up without any benefit.
	 * The message may get retransmitted, though.
	 * Normal retry behaviour gets achieved during
	 * state OP_PREPARING anyway. */
	tk->proposer = local;
	tk->new_ballot = next_ballot_number(tk);
	tk->proposed_owner = new_owner;

	tk->retry_number = 0;
	ticket_activate_timeout(tk);

	/* TODO: shorten renew exchange by just sending
	 * a new proposal? Ballot numbers should still be the
	 * same everywhere, owner doesn't change. */
	return ticket_broadcast_proposed_state(tk, OP_PREPARING);
}



/** Answering OP_PREPARING means sending out OP_PROMISING. */
inline static int answer_PREP(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		uint32_t ballot,
		struct booth_site *new_owner)
{
	if (!(local->role & ACCEPTOR))
		return 0;

	/* Ignore if packet is too late, and state is already active. */
	if (tk->owner == new_owner &&
			ballot == tk->last_ack_ballot)
		return 0;

	/* We have to be careful here.
	 * Getting multiple copies of the same message must not trigger
	 * rejections, but only repeated promises. */
	if (from == tk->proposer &&
			ballot == tk->new_ballot)
		goto promise;


	/* It doesn't matter whether it's the same or another host;
	 * the only distinction is the ballot number. */
	if (ballot > tk->new_ballot) {
promise:
		msg->header.cmd         = htonl(OP_PROMISING);
		msg->ticket.prev_ballot = htonl(tk->last_ack_ballot);

		set_proposal_in_ticket(tk, from, ballot, new_owner);

		log_info("PROMISING for ticket \"%s\" (by %s) for %d",
				tk->name, from->addr_string, ballot);
	} else {
		msg->header.cmd         = htonl(OP_REJECTED);
		msg->ticket.ballot      = htonl(tk->new_ballot);
		msg->ticket.prev_ballot = htonl(tk->last_ack_ballot);

		log_info("REJECTING (prep) for ticket \"%s\" from %s - have %d, wanted %d",
				tk->name, from->addr_string,
				tk->new_ballot, ballot);
	}
	init_header_bare(&msg->header);
	return booth_udp_send(from, msg, sizeof(*msg));
}


/** Getting OP_REJECTED means abandoning the current operation. */
inline static int handle_REJ(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		uint32_t ballot,
		struct booth_site *new_owner)
{
	if (tk->last_ack_ballot == ballot) {
		log_debug("got a late REJECTED; ignored, as "
				"ballot %d is already active.",
				tk->last_ack_ballot);
		return 0;
	}


	log_info("got REJECTED for ticket \"%s\", ballot %d (has %d), from %s",
			tk->name,
			tk->new_ballot, ballot,
			from->addr_string);

	abort_proposal(tk);

	/* TODO: should we check whether that sequence is increasing? */
	tk->new_ballot = ballot_max2(tk->new_ballot, ballot);
	tk->last_ack_ballot = ballot_max2(tk->last_ack_ballot,
			ntohl(msg->ticket.prev_ballot));

	/* No need to ask the others. */
	tk->state = ST_STABLE;
	return 0;
}


/** After a few OP_PROMISING replies we can send out OP_PROPOSING. */
inline static int got_a_PROM(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		uint32_t ballot,
		struct booth_site *new_owner)
{
	int had_that;

	if (tk->proposer == local &&
			tk->state == OP_PREPARING &&
			tk->new_ballot == ballot) {
		had_that = tk->proposal_acknowledges & from->bitmask;

		tk->proposal_acknowledges |= from->bitmask;

		log_info("Got PROMISE from %s for \"%s\", for %d, acks now 0x%" PRIx64,
				from->addr_string, tk->name,
				tk->new_ballot,
				tk->proposal_acknowledges);
		if (had_that)
			return 0;

		return PREPARE_to_PROPOSE(tk);
	}


	/* Packet just delayed? Silently ignore. */
	if (ballot == tk->last_ack_ballot &&
			(new_owner == tk->owner ||
			 new_owner == tk->proposed_owner))
		return 0;

	/* Message sent to wrong host? */
	log_debug("got unexpected PROMISE from %s for \"%s\"",
			from->addr_string, tk->name);

	return 0;
}


/** Answering OP_PROPOSING means sending out OP_ACCEPTING. */
inline static int answer_PROP(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		uint32_t ballot,
		struct booth_site *new_owner)
{
	if (!(local->role & ACCEPTOR))
		return 0;


	/* Repeated packet. */
	if (new_owner == tk->owner &&
			ballot == tk->new_ballot)
		goto accepting;

	/* If packet is late, ie. we already have that state,
	 * just repeat the ack - perhaps it got lost. */
	if (new_owner == tk->owner &&
			ballot == tk->last_ack_ballot)
		goto accepting;


	/* We have to be careful here.
	 * Getting multiple copies of the same message must not trigger
	 * rejections, but only repeated OP_ACCEPTING messages. */
	if (ballot > tk->last_ack_ballot &&
			ballot == tk->new_ballot &&
			ntohl(msg->ticket.prev_ballot) == tk->last_ack_ballot) {
		if (tk->proposer) {
			/* Send OP_REJECTED to previous proposer? */
			log_info("new PROPOSAL for ticket \"%s\" overriding older one from %s",
					tk->name, from->addr_string);
		}

		tk->proposer = from;

accepting:
		init_ticket_msg(msg, OP_ACCEPTING, RLT_SUCCESS, tk);

		log_info("sending ACCEPT for ticket \"%s\" (by %s) for %d - new owner %s",
				tk->name, from->addr_string, ballot,
				ticket_owner_string(new_owner));
		change_ticket_owner(tk, ballot, new_owner);
	} else if (ballot == tk->last_ack_ballot &&
			ballot == tk->new_ballot &&
			ntohl(msg->ticket.prev_ballot) == tk->last_ack_ballot) {
		/* Silently ignore delayed messages. */
	} else {
		msg->header.cmd         = htonl(OP_REJECTED);
		msg->ticket.ballot      = htonl(tk->new_ballot);
		msg->ticket.prev_ballot = htonl(tk->last_ack_ballot);

		log_info("REJECTING (prop) for ticket \"%s\" from %s - have %d, wanted %d",
				tk->name, from->addr_string,
				tk->new_ballot, ballot);
	}
	init_header_bare(&msg->header);
	return booth_udp_send(from, msg, sizeof(*msg));
}


/** After enough OP_ACCEPTING we can do the change, and send an OP_COMMITTED. */
inline static int got_an_ACC(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		uint32_t ballot,
		struct booth_site *new_owner)
{
	if (tk->proposer == local &&
			tk->state == OP_PROPOSING) {
		tk->proposal_acknowledges |= from->bitmask;

		log_info("Got ACCEPTING from %s for \"%s\", acks now 0x%" PRIx64,
				from->addr_string, tk->name,
				tk->proposal_acknowledges);

		return PROPOSE_to_COMMIT(tk);
	}
	return 0;
}


/** An OP_COMMITTED gets no answer; just record the new state. */
inline static int answer_COMM(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		uint32_t ballot,
		struct booth_site *new_owner)
{
	/* We cannot check whether the packet is from an expected proposer -
	 * perhaps this is the _only_ message of the whole handshake? */

	if (ballot > tk->new_ballot &&
			ntohl(msg->ticket.prev_ballot) == tk->last_ack_ballot) {
		change_ticket_owner(tk, ballot, new_owner);
	} else {
		log_info("commit message from \"%s\" discarded.", from->addr_string);
	}

	/* Send ack? */
	return 0;

}

/** @} */


int paxos_answer(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		uint32_t ballot,
		struct booth_site *new_owner_p)
{
	int cmd;

	cmd = ntohl(msg->header.cmd);

	/* These are in roughly chronological order.
	 * What the first machine sends is an OP_PREPARING
	 * (see paxos_start_round()), which gets received
	 * (below) from the others ... */
	switch (cmd) {
	case OP_PREPARING:
		return answer_PREP(tk, from, msg, ballot, new_owner_p);

	case OP_REJECTED:
		return handle_REJ(tk, from, msg, ballot, new_owner_p);

	case OP_PROMISING:
		return got_a_PROM(tk, from, msg, ballot, new_owner_p);

	case OP_PROPOSING:
		return answer_PROP(tk, from, msg, ballot, new_owner_p);

	case OP_ACCEPTING:
		return got_an_ACC(tk, from, msg, ballot, new_owner_p);

	case OP_COMMITTED:
		return answer_COMM(tk, from, msg, ballot, new_owner_p);

	default:
		log_error("unprocessed message, cmd %x", cmd);
		return -EINVAL;
	}
}
