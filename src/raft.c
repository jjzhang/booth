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
			who->addr_string,
			vote->addr_string);

	if (!tk->votes_for[who->index]) {
		tk->votes_for[who->index] = vote;
		tk->votes_received |= who->bitmask;
	} else {
		if (tk->votes_for[who->index] != vote)
			log_error("voted previously (but in same term!) for \"%s\"...",
					tk->votes_for[who->index]->addr_string);
	}
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

static int answer_HEARTBEAT (
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	uint32_t term;
	uint32_t index;

	term = ntohl(msg->ticket.term);
	log_debug("leader: %s, have %s; term %d vs %d",
			site_string(leader), ticket_leader_string(tk),
			term, tk->current_term);
	if (term < tk->current_term)
		return 0; //send_reject(sender, tk, RLT_TERM_OUTDATED);

	/* § 5.3 */
	index = ntohl(msg->ticket.leader_commit);
	if (index > tk->commit_index)
		tk->commit_index = index;

	assert(tk->leader == leader);


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
	if (term < tk->current_term)
		return send_reject(sender, tk, RLT_TERM_OUTDATED);

	if (term > tk->current_term)
		clear_election(tk);

	site_voted_for(tk, sender, leader);


	/* §5.2 */
	new_leader = majority_votes(tk);
	if (new_leader) {
		tk->leader = new_leader;

		if ( new_leader == local)  {
			tk->current_term++;
			tk->state = ST_LEADER;
			send_heartbeat(tk);
			tk->voted_for = NULL;
		}
		else
			tk->state = ST_FOLLOWER;

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
	struct boothc_ticket_msg omsg;


	term = ntohl(msg->ticket.term);

	/* §5.1 */
	if (term < tk->current_term)
		return send_reject(sender, tk, RLT_TERM_OUTDATED);

	/* §5.2, §5.4 */
	if (!tk->voted_for &&
			ntohl(msg->ticket.last_log_index) >= tk->last_applied) {
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
			now, tk->election_end);
	if (now <= tk->election_end)
		return 0;


	/* §5.2 */
	tk->current_term++;
	tk->election_end = now + tk->term_duration;

	log_debug("start new election! term=%d, until %" PRIi64,
			tk->current_term, tk->election_end);
	clear_election(tk);

	if(preference)
		new_leader = preference;
	else
		new_leader = (local->type == SITE) ? local : NULL;
	site_voted_for(tk, local, new_leader);
	tk->voted_for = new_leader;

	tk->state = ST_CANDIDATE;

	ticket_broadcast(tk, OP_REQ_VOTE, RLT_SUCCESS);
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
	uint32_t term;

	cmd = ntohl(msg->header.cmd);
	term = ntohl(msg->ticket.term);

	log_debug("got message %s from \"%s\", term %d vs. %d",
			state_to_string(cmd),
			from->addr_string,
			term, tk->current_term);

	/* §5.1 */
	if (term > tk->current_term) {
		tk->state = ST_FOLLOWER;
		tk->current_term = term;
		tk->leader = leader;
		log_info("higher term %d vs. %d, following \"%s\"",
				term, tk->current_term,
				ticket_leader_string(tk));
	}


	switch (cmd) {
	case OP_REQ_VOTE:
		return answer_REQ_VOTE (tk, from, leader, msg);
	case OP_VOTE_FOR:
		return process_VOTE_FOR(tk, from, leader, msg);
	case OP_HEARTBEAT:
		return answer_HEARTBEAT(tk, from, leader, msg);
	case OP_REJECTED:
		return process_REJECTED(tk, from, leader, msg);
	}
	log_error("unprocessed message, cmd %x", cmd);
	return -EINVAL;
}
