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
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "ticket.h"
#include "config.h"
#include "pacemaker.h"
#include "inline-fn.h"
#include "log.h"
#include "booth.h"
#include "raft.h"
#include "handler.h"

#define TK_LINE			256


/* Untrusted input, must fit (incl. \0) in a buffer of max chars. */
int check_max_len_valid(const char *s, int max)
{
	int i;
	for(i=0; i<max; i++)
		if (s[i] == 0)
			return 1;
	return 0;
}

int find_ticket_by_name(const char *ticket, struct ticket_config **found)
{
	int i;

	if (found)
		*found = NULL;

	for (i = 0; i < booth_conf->ticket_count; i++) {
		if (!strcmp(booth_conf->ticket[i].name, ticket)) {
			if (found)
				*found = booth_conf->ticket + i;
			return 1;
		}
	}

	return 0;
}


int check_ticket(char *ticket, struct ticket_config **found)
{
	if (found)
		*found = NULL;
	if (!booth_conf)
		return 0;

	if (!check_max_len_valid(ticket, sizeof(booth_conf->ticket[0].name)))
		return 0;
	return find_ticket_by_name(ticket, found);
}

int check_site(char *site, int *is_local)
{
	struct booth_site *node;

	if (!check_max_len_valid(site, sizeof(node->addr_string)))
		return 0;

	if (find_site_by_name(site, &node, 0)) {
		*is_local = node->local;
		return 1;
	}

	return 0;
}


#if 0
/** Find out what others think about this ticket.
 *
 * If we're a SITE, we can ask (and have to tell) Pacemaker.
 * An ARBITRATOR can only ask others. */
static int ticket_send_catchup(struct ticket_config *tk)
{
	int i, rv = 0;
	struct booth_site *site;
	struct boothc_ticket_msg msg;

	foreach_node(i, site) {
		if (!site->local) {
			init_ticket_msg(&msg, CMD_CATCHUP, RLT_SUCCESS, tk);

			log_debug("attempting catchup from %s", site->addr_string);

			rv = booth_udp_send(site, &msg, sizeof(msg));
		}
	}

	ticket_activate_timeout(tk);

	return rv;
}
#endif


int ticket_write(struct ticket_config *tk)
{
	if (local->type != SITE)
		return -EINVAL;

	disown_if_expired(tk);

	if (tk->leader == local) {
		pcmk_handler.grant_ticket(tk);
	} else {
		pcmk_handler.revoke_ticket(tk);
	}

	return 0;
}


/* Ask an external program whether getting the ticket
 * makes sense.
* Eg. if the services have a failcount of INFINITY,
* we can't serve here anyway. */
int get_ticket_locally_if_allowed(struct ticket_config *tk)
{
	int rv;

	if (!tk->ext_verifier)
		goto get_it;

	rv = run_handler(tk, tk->ext_verifier, 1);
	if (rv) {
		log_error("May not acquire ticket.");

		/* Give it to somebody else.
		 * Just send a commit message, as the
		 * others couldn't help anyway. */
		if (leader_and_valid(tk)) {
			disown_ticket(tk);
#if 0
			tk->proposed_owner = NULL;

			/* Just go one further - others may easily override. */
			tk->new_ballot++;

			ticket_broadcast_proposed_state(tk, OP_COMMITTED);
			tk->state = ST_STABLE;
#endif
			ticket_broadcast(tk, OP_VOTE_FOR, RLT_SUCCESS);
		}

		return rv;
	} else {
		log_info("May keep ticket.");
	}

get_it:
	if (leader_and_valid(tk)) {
		return send_heartbeat(tk);
	}
	else {
		new_election(tk, local);
		return ticket_broadcast(tk, OP_REQ_VOTE, RLT_SUCCESS);
	}
#if 0
	return paxos_start_round(tk, local);
#endif
}


/** Try to get the ticket for the local site.
 * */
int do_grant_ticket(struct ticket_config *tk)
{
	int rv;

	if (tk->leader == local)
		return RLT_SUCCESS;
	if (tk->leader)
		return RLT_OVERGRANT;

	rv = get_ticket_locally_if_allowed(tk);
	return rv;
}


/** Start a PAXOS round for revoking.
 * That can be started from any site. */
int do_revoke_ticket(struct ticket_config *tk)
{
	int rv;

	if (!tk->leader)
		return RLT_SUCCESS;

	disown_ticket(tk);
	ticket_write(tk);
	return ticket_broadcast(tk, OP_REQ_VOTE, RLT_SUCCESS);
#if 0
	rv = paxos_start_round(tk, NULL);
#endif

	return rv;
}


int list_ticket(char **pdata, unsigned int *len)
{
	struct ticket_config *tk;
	char timeout_str[64];
	char *data, *cp;
	int i, alloc;

	*pdata = NULL;
	*len = 0;

	alloc = 256 +
		booth_conf->ticket_count * (BOOTH_NAME_LEN * 2 + 128);
	data = malloc(alloc);
	if (!data)
		return -ENOMEM;

	cp = data;
	foreach_ticket(i, tk) {
		if (tk->term_expires != 0)
			strftime(timeout_str, sizeof(timeout_str), "%F %T",
					localtime(&tk->term_expires));
		else
			strcpy(timeout_str, "INF");


		cp += sprintf(cp,
				"ticket: %s, leader: %s, expires: %s, commit: %d\n",
				tk->name,
				ticket_leader_string(tk),
				timeout_str,
				tk->commit_index);

		*len = cp - data;
		assert(*len < alloc);
	}

	*pdata = data;

	return 0;
}


int setup_ticket(void)
{
	struct ticket_config *tk;
	int i;

	 /* TODO */
	foreach_ticket(i, tk) {
		tk->leader = NULL;
		tk->term_expires = 0;

		//		abort_proposal(tk);

		if (local->type == SITE) {
			pcmk_handler.load_ticket(tk);
		}

		/* There might be a leader; wait for its notification. */
		tk->term_expires = time(NULL) + tk->term_duration;
		tk->state = ST_FOLLOWER;
	}


	return 0;
}


int ticket_answer_list(int fd, struct boothc_ticket_msg *msg)
{
	char *data;
	int olen, rv;
	struct boothc_header hdr;

	rv = list_ticket(&data, &olen);
	if (rv < 0)
		return rv;

	init_header(&hdr, CMR_LIST, RLT_SUCCESS, sizeof(hdr) + olen);

	return send_header_plus(fd, &hdr, data, olen);
}


int ticket_answer_grant(int fd, struct boothc_ticket_msg *msg)
{
	int rv;
	struct ticket_config *tk;


	if (!check_ticket(msg->ticket.id, &tk)) {
		log_error("Client asked to grant unknown ticket");
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	if (tk->leader) {
		log_error("client wants to get an (already granted!) ticket \"%s\"",
				msg->ticket.id);
		rv = RLT_OVERGRANT;
		goto reply;
	}

	rv = do_grant_ticket(tk);

reply:
	init_header(&msg->header, CMR_GRANT, rv ?: RLT_ASYNC, sizeof(*msg));
	return send_ticket_msg(fd, msg);
}


int ticket_answer_revoke(int fd, struct boothc_ticket_msg *msg)
{
	int rv;
	struct ticket_config *tk;

	if (!check_ticket(msg->ticket.id, &tk)) {
		log_error("Client asked to grant unknown ticket");
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	if (!tk->leader) {
		log_info("client wants to revoke a free ticket \"%s\"",
				msg->ticket.id);
		/* Return a different result code? */
		rv = RLT_SUCCESS;
		goto reply;
	}

	rv = do_revoke_ticket(tk);
	if (rv == 0)
		rv = RLT_ASYNC;

reply:
	init_ticket_msg(msg, CMR_REVOKE, rv, tk);
	return send_ticket_msg(fd, msg);
}


int ticket_broadcast(struct ticket_config *tk, cmd_request_t cmd, cmd_result_t res)
{
	struct boothc_ticket_msg msg;

	init_ticket_msg(&msg, cmd, res, tk);
	log_debug("broadcasting '%s' for ticket \"%s\"",
			state_to_string(cmd), tk->name);

	return transport()->broadcast(&msg, sizeof(msg));
}


#if 0
/** Send new state request to all sites.
 * Perhaps this should take a flag for ACCEPTOR etc.?
 * No need currently, as all nodes are more or less identical. */
int ticket_broadcast_proposed_state(struct ticket_config *tk, cmd_request_t state)
{
	struct boothc_ticket_msg msg;

	tk->state                 = state;
	init_ticket_msg(&msg, state, RLT_SUCCESS, tk);
	msg.ticket.leader         = htonl(get_node_id(tk->proposed_owner));

	log_debug("broadcasting '%s' for ticket \"%s\"",
			state_to_string(state), tk->name);

	/* Switch state after one second, if the majority says ok. */
	gettimeofday(&tk->proposal_switch, NULL);
	tk->proposal_switch.tv_sec++;


	return transport()->broadcast(&msg, sizeof(msg));
}
#endif


static void ticket_cron(struct ticket_config *tk)
{
	time_t now;

	now = time(NULL);


	R(tk);
	/* Has an owner, has an expiry date, and expiry date in the past?
	 * Losing the ticket must happen in _every_ state. */
	if (tk->term_expires &&
			tk->leader &&
			now > tk->term_expires) {
		log_info("LOST ticket: \"%s\" no longer at %s",
				tk->name,
				ticket_leader_string(tk));

		/* Couldn't renew in time - ticket lost. */
		disown_ticket(tk);

		/* New vote round; §5.2 */
		if (local->type == SITE)
			new_election(tk, NULL);
/* should be "always" that way
		else
			tk->state = ST_FOLLOWER;
 */
//		abort_proposal(tk); TODO

		ticket_write(tk);

		ticket_activate_timeout(tk);

		/* May not try to re-acquire now, need to find out
		 * what others think. */
		return;
	}

	R(tk);

	switch(tk->state) {
	case ST_INIT:
		/* Unknown state, ask others. */
//		ticket_send_catchup(tk);
		break;


	case ST_FOLLOWER:
		if (tk->term_expires &&
				now > tk->term_expires) {
			new_election(tk, NULL);
		}
		break;

	case ST_CANDIDATE:
		/* §5.2 */
		if (now > tk->election_end)
			new_election(tk, NULL);
		break;

	case ST_LEADER:
		if (tk->hb_sent_at + tk->timeout > now) {
			/* Heartbeat timeout reached. Oops ... */
			tk->retry_number ++;
			log_error("Not enough answers to heartbeat on try #%d: "
					"only got %d answers (mask 0x%" PRIx64 ")!",
					tk->retry_number,
					count_bits(tk->hb_received),
					tk->hb_received);

			/* Don't give up, though - there's still some time until leadership is lost. */
		}
		tk->term_expires = now + tk->term_duration;
		send_heartbeat(tk);
		ticket_write(tk);
		ticket_activate_timeout(tk);
		// set_ticket_wakeup(tk);
		break;

	default:
		break;
	}
	R(tk);
}


void process_tickets(void)
{
	struct ticket_config *tk;
	int i;
	struct timeval now;
	float sec_until;

	gettimeofday(&now, NULL);

	foreach_ticket(i, tk) {
		sec_until = timeval_to_float(tk->next_cron) - timeval_to_float(now);
		if (0)
			log_debug("ticket %s next cron %" PRIx64 ".%03d, "
					"now %" PRIx64 "%03d, in %f",
					tk->name,
					(uint64_t)tk->next_cron.tv_sec, timeval_msec(tk->next_cron),
					(uint64_t)now.tv_sec, timeval_msec(now),
					sec_until);
		if (sec_until > 0.0)
			continue;

		log_debug("ticket cron: doing %s", tk->name);


		/* Set next value, handler may override.
		 * This should already be handled via the state logic;
		 * but to be on the safe side the renew repetition is
		 * duplicated here, too.  */
		set_ticket_wakeup(tk);

		ticket_cron(tk);
	}
}



void tickets_log_info(void)
{
	struct ticket_config *tk;
	int i;

	foreach_ticket(i, tk) {
		log_info("Ticket %s: state '%s' "
				"commit index %d "
				"leader \"%s\" "
				"expires %-24.24s",
				tk->name,
				state_to_string(tk->state),
				tk->commit_index,
				ticket_leader_string(tk),
				ctime(&tk->term_expires));
	}
}


/* UDP message receiver. */
int message_recv(struct boothc_ticket_msg *msg, int msglen)
{
	uint32_t from;
	struct booth_site *source;
	struct ticket_config *tk;
	struct booth_site *leader;
	uint32_t leader_u;


	if (check_boothc_header(&msg->header, sizeof(*msg)) < 0 ||
			msglen != sizeof(*msg)) {
		log_error("message receive error");
		return -1;
	}

	from = ntohl(msg->header.from);
	if (!find_site_by_id(from, &source) || !source) {
		log_error("unknown sender: %08x", from);
		return -1;
	}

	if (!check_ticket(msg->ticket.id, &tk)) {
		log_error("got invalid ticket name \"%s\" from %s",
				msg->ticket.id, source->addr_string);
		return -EINVAL;
	}


	leader_u = ntohl(msg->ticket.leader);
	if (!find_site_by_id(leader_u, &leader)) {
		log_error("Message with unknown owner %x received", leader_u);
		return -EINVAL;
	}


	return raft_answer(tk, source, leader, msg);
}


void set_ticket_wakeup(struct ticket_config *tk)
{
	struct timeval tv, now;

	/* At least every hour, perhaps sooner. */
	ticket_next_cron_in(tk, 3600);

	switch (tk->state) {
	case ST_LEADER:
		assert(tk->leader == local);
		gettimeofday(&now, NULL);

		tv = now;
		tv.tv_sec = next_vote_starts_at(tk);

		/* If timestamp is in the past, look again in one second. */
		if (timeval_compare(tv, now) <= 0)
			tv.tv_sec = now.tv_sec + 1;

		ticket_next_cron_at(tk, tv);
		break;

	case ST_CANDIDATE:
		assert(tk->election_end);
		ticket_next_cron_at_coarse(tk, tk->election_end);
		break;

	case ST_INIT:
	case ST_FOLLOWER:
		/* If there is (or should be) some owner, check on her later on.
		 * If no one is interested - don't care. */
		if ((tk->leader || tk->acquire_after) &&
				(local->type == SITE))
			ticket_next_cron_at_coarse(tk,
					tk->term_expires + tk->acquire_after);
		break;

	default:
		log_error("why here?");
	}
}



/* Given a state (in host byte order), return a human-readable (char*).
 * An array is used so that multiple states can be printed in a single printf(). */
char *state_to_string(uint32_t state_ho)
{
	union mu { cmd_request_t s; char c[5]; };
	static union mu cache[6] = { { 0 } }, *cur;
	static int current = 0;

	current ++;
	if (current >= sizeof(cache)/sizeof(cache[0]))
		current = 0;

	cur = cache + current;

	cur->s = htonl(state_ho);
	/* Shouldn't be necessary, union array is initialized with zeroes, and
	 * these bytes never get written. */
	cur->c[4] = 0;
	return cur->c;
}


int send_reject(struct booth_site *dest, struct ticket_config *tk, cmd_result_t code)
{
	struct boothc_ticket_msg msg;


	init_ticket_msg(&msg, OP_REJECTED, code, tk);
	return booth_udp_send(dest, &msg, sizeof(msg));
}
