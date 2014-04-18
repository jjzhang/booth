/*
 * Copyright (C) 2014 Philipp Marek <philipp.marek@linbit.com>
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
#include "raft.h"
#include "ticket.h"
#include "log.h"



inline static void clear_election(struct ticket_config *tk)
{
	int i;
	struct booth_site *site;

	log_info("clear election");
	tk->votes_received = 0;
	foreach_node(i, site)
		tk->votes_for[site->index] = NULL;
}


inline static void site_voted_for(struct ticket_config *tk,
		struct booth_site *who,
		struct booth_site *vote)
{
	log_info("site \"%s\" votes for \"%s\"",
			site_string(who),
			site_string(vote));

	if (!tk->votes_for[who->index]) {
		tk->votes_for[who->index] = vote;
		tk->votes_received |= who->bitmask;
	} else {
		if (tk->votes_for[who->index] != vote)
			log_error("voted previously (but in same term!) for \"%s\"...",
					tk->votes_for[who->index]->addr_string);
	}
}


static void become_follower(struct ticket_config *tk,
		struct boothc_ticket_msg *msg)
{
	uint32_t i;
	int duration;

	tk->state = ST_FOLLOWER;


	duration = tk->term_duration;
	if (msg)
		duration = min(duration, ntohl(msg->ticket.term_valid_for));
	tk->term_expires = time(NULL) + duration;


	if (msg) {
		i = ntohl(msg->ticket.term);
		tk->current_term = max(i, tk->current_term);

		/* § 5.3 */
		i = ntohl(msg->ticket.leader_commit);
		tk->commit_index = max(i, tk->commit_index);
	}


	ticket_write(tk);
}


static struct booth_site *majority_votes(struct ticket_config *tk)
{
	int i, n;
	struct booth_site *v;
	int count[MAX_NODES] = { 0, };


	for(i=0; i<booth_conf->site_count; i++) {
		v = tk->votes_for[i];
		if (!v)
			continue;

		n = v->index;
		count[n]++;
		log_info("Majority: %d \"%s\" wants %d \"%s\" => %d",
				i, booth_conf->site[i].addr_string,
				n, v->addr_string,
				count[n]);

		if (count[n]*2 <= booth_conf->site_count)
			continue;


		log_info("Majority reached: %d of %d for \"%s\"",
				count[n], booth_conf->site_count,
				v->addr_string);
		return v;
	}

	return NULL;
}


static int newer_term(struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg)
{
	uint32_t term;

	term = ntohl(msg->ticket.term);
	/* §5.1 */
	if (term > tk->current_term) {
		tk->state = ST_FOLLOWER;
		tk->leader = leader;
		log_info("higher term %d vs. %d, following \"%s\"",
				term, tk->current_term,
				ticket_leader_string(tk));

		tk->term_expires = time(NULL) + tk->term_duration;
		tk->current_term = term;
		return 1;
	}

	return 0;
}

static int term_too_low(struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg)
{
	uint32_t term;

	term = ntohl(msg->ticket.term);
	/* §5.1 */
	if (term < tk->current_term)
	{
		log_info("sending REJECT, term too low.");
		send_reject(sender, tk, RLT_TERM_OUTDATED);
		return 1;
	}

	return 0;
}




/* For follower. */
static int answer_HEARTBEAT (
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	uint32_t term;
	struct boothc_ticket_msg omsg;


	term = ntohl(msg->ticket.term);
	log_debug("leader: %s, have %s; term %d vs %d",
			site_string(leader), ticket_leader_string(tk),
			term, tk->current_term);

	/* No reject. (?) */
	if (term < tk->current_term) {
		log_info("ignoring lower term %d vs. %d, from \"%s\"",
				term, tk->current_term,
				ticket_leader_string(tk));
		return 0;
	}

	/* Needed? */
	newer_term(tk, sender, leader, msg);

	become_follower(tk, msg);
	/* Racy??? */
	assert(sender == leader || !leader);

	tk->leader = leader;

	/* run ticket_cron if the ticket expires */
	set_ticket_wakeup(tk);

	/* Ack the heartbeat (we comply). */
	init_ticket_msg(&omsg, OP_HEARTBEAT, RLT_SUCCESS, tk);
	return booth_udp_send(sender, &omsg, sizeof(omsg));
}


/* For leader. */
static int process_HEARTBEAT(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	uint32_t term;


	if (newer_term(tk, sender, leader, msg)) {
		/* Uh oh. Higher term?? Should we simply believe that? */
		log_error("Got higher term number from");
		return 0;
	}


	term = ntohl(msg->ticket.term);

	/* Don't send a reject. */
	if (term < tk->current_term) {
		/* Doesn't know what he's talking about - perhaps
		 * doesn't receive our packets? */
		log_error("Stale/wrong heartbeat from \"%s\": "
				"term %d instead of %d",
				site_string(sender),
				term, tk->current_term);
		return 0;
	}


	if (term == tk->current_term &&
			leader == tk->leader) {
		/* Hooray, an ACK! */
		/* So at least _someone_ is listening. */
		tk->hb_received |= sender->bitmask;

		log_debug("Got heartbeat ACK from \"%s\", %d/%d agree.",
				site_string(sender),
				count_bits(tk->hb_received),
				booth_conf->site_count);


		if (majority_of_bits(tk, tk->hb_received)) {
			/* OK, at least half of the nodes are reachable;
			 * no need to do anything until
			 * the next heartbeat should be sent. */
			if( !tk->majority_acks_received ) {
			/* Write the ticket to the CIB and set the next
			 * wakeup time (but do that only once) */
				tk->majority_acks_received = 1;
				set_ticket_wakeup(tk);
				tk->retry_number = 0;
				ticket_write(tk);
			}
		}
	}

	return 0;
}


static int process_VOTE_FOR(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
		)
{
	uint32_t term;
	struct booth_site *new_leader;


	term = ntohl(msg->ticket.term);
	if (term_too_low(tk, sender, leader, msg))
		return 0;


	if (term == tk->current_term &&
			tk->election_end < time(NULL)) {
		/* Election already ended - either by time or majority.
		 * Ignore. */
		return 0;
	}


	if (newer_term(tk, sender, leader, msg)) {
		clear_election(tk);
	}


	site_voted_for(tk, sender, leader);


	/* §5.2 */
	new_leader = majority_votes(tk);
	if (new_leader) {
		tk->leader = new_leader;

		tk->term_expires = time(NULL) + tk->term_duration;
		tk->election_end = 0;
		tk->voted_for = NULL;

		if ( new_leader == local)  {
			tk->commit_index++; // ??
			tk->state = ST_LEADER;
			send_heartbeat(tk);
		}
		else
			become_follower(tk, NULL);
	}

	set_ticket_wakeup(tk);
	return 0;
}


static int process_REJECTED(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
		)
{
	uint32_t rv;

	rv   = ntohl(msg->header.result);

	if (tk->state == ST_CANDIDATE &&
			rv == RLT_TERM_OUTDATED) {
		log_info("Am out of date, become follower.");
		tk->leader = leader;
		become_follower(tk, msg);
		return 0;
	}


	if (tk->state == ST_CANDIDATE &&
			rv == RLT_TERM_STILL_VALID) {
		log_error("There's a leader that I don't see: \"%s\"",
				site_string(leader));
		tk->leader = leader;
		become_follower(tk, msg);
		return 0;
	}

	log_error("unhandled reject: in state %s, got %s.",
			state_to_string(tk->state),
			state_to_string(rv));
	tk->leader = leader;
	become_follower(tk, msg);
	return 0;
}


/* §5.2 */
static int answer_REQ_VOTE(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
		)
{
	uint32_t term;
	int valid;
	struct boothc_ticket_msg omsg;


	if (leader == no_leader)
		return 0;
	if (term_too_low(tk, sender, leader, msg))
		return 0;
	if (newer_term(tk, sender, leader, msg))
		goto vote_for_sender;


	term = ntohl(msg->ticket.term);
	/* Important: Ignore duplicated packets! */
	valid = term_time_left(tk);
	if (valid &&
			term == tk->current_term &&
			sender == tk->leader) {
		log_debug("Duplicate OP_VOTE_FOR ignored.");
		return 0;
	}

	if (valid) {
		log_debug("no election allowed, term valid for %d??", valid);
		return send_reject(sender, tk, RLT_TERM_STILL_VALID);
	}

	/* §5.2, §5.4 */
	if (!tk->voted_for) {
vote_for_sender:
		tk->voted_for = sender;
		site_voted_for(tk, sender, leader);
		goto yes_you_can;
	}


yes_you_can:
	init_ticket_msg(&omsg, OP_VOTE_FOR, RLT_SUCCESS, tk);
	omsg.ticket.leader = htonl(get_node_id(tk->voted_for));

	return transport()->broadcast(&omsg, sizeof(omsg));
}


int new_election(struct ticket_config *tk, struct booth_site *preference)
{
	struct booth_site *new_leader;
	time_t now;


	time(&now);
	log_debug("start new election?, now=%" PRIi64 ", end %" PRIi64,
			(int64_t)now, (int64_t)(tk->election_end));
	if (now <= tk->election_end)
		return 0;


	/* §5.2 */
	/* If there was _no_ answer, don't keep incrementing the term number
	 * indefinitely. If there was no peer, there'll probably be no one
	 * listening now either. However, we don't know if we were
	 * invoked due to a timeout. It's up to the caller to
	 * increment the term!
	tk->current_term++;
	 */

	tk->term_expires = 0;
	tk->election_end = now + tk->term_duration;

	log_debug("start new election! term=%d, until %" PRIi64,
			tk->current_term, (int64_t)tk->election_end);
	clear_election(tk);

	if(preference)
		new_leader = preference;
	else
		new_leader = (local->type == SITE) ? local : NULL;
	site_voted_for(tk, local, new_leader);
	tk->voted_for = new_leader;

	tk->state = ST_CANDIDATE;

	ticket_broadcast(tk, OP_REQ_VOTE, RLT_SUCCESS);
	ticket_activate_timeout(tk);
	return 0;
}


int raft_answer(
		struct ticket_config *tk,
		struct booth_site *from,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	int cmd;
	int rv;

	rv = 0;
	cmd = ntohl(msg->header.cmd);
	R(tk);

	log_debug("got message %s from \"%s\"",
			state_to_string(cmd),
			from->addr_string);


	switch (cmd) {
	case OP_REQ_VOTE:
		rv = answer_REQ_VOTE(tk, from, leader, msg);
		break;
	case OP_VOTE_FOR:
		rv = process_VOTE_FOR(tk, from, leader, msg);
		break;
	case OP_HEARTBEAT:
		if (tk->leader == local &&
				tk->state == ST_LEADER)
			rv = process_HEARTBEAT(tk, from, leader, msg);
		else if (tk->leader != local &&
				tk->state == ST_FOLLOWER)
			rv = answer_HEARTBEAT(tk, from, leader, msg);
		else
			assert("invalid combination - leader, follower");
		break;
	case OP_REJECTED:
		rv = process_REJECTED(tk, from, leader, msg);
		break;
	default:
		log_error("unprocessed message, cmd %x", cmd);
		rv = -EINVAL;
	}
	R(tk);
	return rv;
}
