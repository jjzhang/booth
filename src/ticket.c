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
#include "paxos.h"

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

	if (find_site_by_name(site, &node)) {
		*is_local = node->local;
		return 1;
	}

	return 0;
}


static inline int is_same_or_better_state(cmd_request_t here, cmd_request_t there)
{
	if (here == there)
		return 1;

	if (here == ST_INIT)
		return 1;

	return 0;
}


static void combine_paxos_states(struct ticket_config *tk,
	struct ticket_paxos_state *new)
{
	struct ticket_paxos_state *is;

	is  = &tk->proposed_state;

	log_info("combine %s: state %s->%s "
			"mask %" PRIx64 "/%" PRIx64 " "
			"ballot %x/%x ",
			tk->name,
			STATE_STRING(is->state),
			STATE_STRING(new->state),
			is->acknowledges, new->acknowledges,
			is->ballot,       new->ballot);

	if (is->ballot > new->ballot) {
		log_debug("ticket %s got older ballot %d %d, ignored.",
				tk->name, is->ballot, new->ballot);
		return;
	}

	if (is->ballot < new->ballot) {
		log_debug("ticket %s got newer ballot %d %d, loaded.",
				tk->name, is->ballot, new->ballot);
		/* Eg. for CATCHUP */
		*is = *new;
		return;
	}

	if (is->prev_ballot != new->prev_ballot) {
		/* Reject? */
		log_debug("ticket %s got different prev ballots %d %d.",
				tk->name, is->prev_ballot, new->prev_ballot);
		return;
	}

	/* ballot numbers the same. */
	if (is_same_or_better_state(is->state, new->state) &&
			is->owner == new->owner) {
		is->acknowledges |= new->acknowledges;
		log_debug("ticket %s got ack %" PRIx64 ", now %" PRIx64,
				tk->name, new->acknowledges, is->acknowledges);
	}
	else {
	}
}


int promote_ticket_state(struct ticket_config *tk)
{
	/* >= or > ? */
	if (__builtin_popcount(tk->proposed_state.acknowledges) * 2 >
			booth_conf->site_count) {
		tk->current_state = tk->proposed_state;

		if (tk->current_state.state == ST_INIT)
			tk->current_state.state = ST_STABLE;

		log_debug("ticket %s changing into state %s",
				tk->name, STATE_STRING(tk->current_state.state));

		return 1;
	}

	return 0;
}


static void ticket_parse(struct ticket_config *tk,
		struct boothc_ticket_msg *tmsg,
		struct booth_site *from)
{
	struct ticket_paxos_state tp, *tps;
	struct booth_site *owner;
	time_t now;


	time(&now);
	tps = &tp;

	if (ntohl(tmsg->header.result) == RLT_SUCCESS) {
		if (!find_site_by_id( ntohl(tmsg->ticket.owner), &owner)) {
			log_error("wrong site_id %x as ticket owner, msg from %x",
					tmsg->ticket.owner, tmsg->header.from);
			return;
		}

		tps->expires     = ntohl(tmsg->ticket.expiry) + now;
		tps->ballot      = ntohl(tmsg->ticket.ballot);
		tps->prev_ballot = ntohl(tmsg->ticket.prev_ballot);
		tps->owner       = owner;
		tps->acknowledges= from->bitmask;
		tps->state       = ST_STABLE;
	}


	if (now >= tps->expires) {
		tps->owner = NULL;
		tps->expires = 0;
	}

	combine_paxos_states(tk, tps);
	promote_ticket_state(tk);

	if (local->type != ARBITRATOR) {
		pcmk_handler.store_ticket(tk);
		if (tps->owner == local)
			pcmk_handler.grant_ticket(tk);
		else
			pcmk_handler.revoke_ticket(tk);
	}
}


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
			init_ticket_msg(&msg, CMD_CATCHUP, RLT_SUCCESS, tk, &tk->current_state);

			log_debug("attempting catchup from %s", site->addr_string);

			rv = booth_udp_send(site, &msg, sizeof(msg));
		}
	}

	return rv;
}


int ticket_write(struct ticket_config *tk)
{
	pcmk_handler.store_ticket(tk);

	if (tk->current_state.owner == local) {
		pcmk_handler.grant_ticket(tk);
	} else if (!tk->current_state.owner) {
		pcmk_handler.revoke_ticket(tk);
	}

	return 0;
}


/* UDP message receiver. */
int message_recv(struct boothc_ticket_msg *msg, int msglen)
{
	int cmd, rv;
	uint32_t from;
	struct booth_site *dest;
	struct ticket_config *tk;


	if (check_boothc_header(&msg->header, sizeof(*msg)) < 0 ||
			msglen != sizeof(*msg)) {
		log_error("message receive error");
		return -1;
	}

	from = ntohl(msg->header.from);
	if (!find_site_by_id(from, &dest)) {
		log_error("unknown sender: %08x", from);
		return -1;
	}

	if (!check_ticket(msg->ticket.id, &tk)) {
		log_error("got invalid ticket name \"%s\" from %s",
				msg->ticket.id, dest->addr_string);
		return -EINVAL;
	}



	cmd = ntohl(msg->header.cmd);
	switch (cmd) {
	case CMD_CATCHUP:
		rv = ticket_answer_catchup(msg, tk);
		if (rv < 0)
			return rv;
		return booth_udp_send(dest, msg, sizeof(*msg));

	case CMR_CATCHUP:
		if (tk->current_state.state == ST_INIT)
			return ticket_process_catchup(msg, tk, dest);
		break;

	default:
		rv = paxos_answer(msg, tk, dest);
		assert((tk->proposed_state.acknowledges & ~booth_conf->site_bits) == 0);
		assert((tk->current_state.acknowledges & ~booth_conf->site_bits) == 0);
		return rv;
	}
	return 0;
}


/** Try to get the ticket for the local site.
 * */
int do_grant_ticket(struct ticket_config *tk)
{
	int rv;

	if (tk->current_state.owner == local)
		return RLT_SUCCESS;
	if (tk->current_state.owner)
		return RLT_OVERGRANT;

	rv = paxos_start_round(tk, local);
	return rv;
}


/** Start a PAXOS round for revoking.
 * That can be started from any site. */
int do_revoke_ticket(struct ticket_config *tk)
{
	int rv;

	if (!tk->current_state.owner)
		return RLT_SUCCESS;

	rv = paxos_start_round(tk, NULL);

	return rv;
}


int list_ticket(char **pdata, unsigned int *len)
{
	struct ticket_config *tk;
	struct ticket_paxos_state *tps;
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
		tps = &tk->current_state;

		if (tps->expires != 0)
			strftime(timeout_str, sizeof(timeout_str), "%F %T",
					localtime(&tps->expires));
		else
			strcpy(timeout_str, "INF");


		cp += sprintf(cp,
				"ticket: %s, owner: %s, expires: %s\n",
				tk->name,
				tps->owner ? tps->owner->addr_string : "None",
				timeout_str);

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
		tk->current_state.owner = NULL;
		tk->current_state.expires = 0;
		tk->current_state.state = ST_INIT;
		tk->proposed_state = tk->current_state;

		if (local->type != ARBITRATOR) {
			pcmk_handler.load_ticket(tk);
		}
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
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	if (tk->current_state.owner) {
		log_error("client want to get an granted "
				"ticket %s", msg->ticket.id);
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
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	if (!tk->current_state.owner) {
		log_info("client want to revoke a free ticket \"%s\"",
				msg->ticket.id);
		rv = RLT_SUCCESS;
		goto reply;
	}

	rv = do_revoke_ticket(tk);

reply:
	init_ticket_msg(msg, CMR_REVOKE, rv ?: RLT_ASYNC, tk, &tk->current_state);
	return send_ticket_msg(fd, msg);
}


int ticket_answer_catchup(struct boothc_ticket_msg *msg, struct ticket_config *tk)
{
	int rv;


	log_debug("got catchup request for \"%s\" from %08x",
			msg->ticket.id, ntohl(msg->header.from));


	if (!msg && !check_ticket(msg->ticket.id, &tk)) {
		rv = RLT_INVALID_ARG;
		goto reply;
	}


	/* We do _always_ answer.
	 * In case all booth daemons are restarted at the same time, nobody
	 * would answer any questions, leading to timeouts and delays.
	 * Just admit we don't know. */

	rv = RLT_SUCCESS;

reply:
	init_ticket_msg(msg, CMR_CATCHUP, rv, tk,
			(tk->current_state.state == ST_INIT ?
			 &tk->proposed_state :
			 &tk->current_state));
	return 1;
}


/* TODO: move all that into paxos.c, like all other message handling? */
int ticket_process_catchup(struct boothc_ticket_msg *msg, struct ticket_config *tk,
		struct booth_site *sender)
{
	int rv;


	log_debug("got catchup answer for \"%s\" from %s",
			msg->ticket.id, sender->addr_string);

	ticket_parse(tk, msg, sender);
	rv = 0;

	log_debug("got catchup result from %s: result %d", sender->addr_string, rv);
	return rv;
}


/** Send new state request to all sites.
 * Perhaps this should take a flag for ACCEPTOR etc.?
 * No need currently, as all nodes are more or less identical. */
int ticket_broadcast_proposed_state(struct ticket_config *tk, cmd_request_t state)
{
	struct boothc_ticket_msg msg;

	tk->proposed_state.acknowledges = local->bitmask;
	tk->proposed_state.state = state;

	init_ticket_msg(&msg, state, RLT_SUCCESS, tk, &tk->proposed_state);

	log_debug("broadcasting %s for ticket \"%s\"",
			STATE_STRING(state), tk->name);

	return transport()->broadcast(&msg, sizeof(msg));
}


static void ticket_cron(struct ticket_config *tk)
{
	time_t now;

	switch(tk->current_state.state) {
	case ST_INIT:
		/* Unknown state, ask others. */
		ticket_send_catchup(tk);
		return;

	default:
		break;
	}

	now = time(NULL);

	switch(tk->proposed_state.state) {
	case OP_COMMITTED:
	case ST_STABLE:

		/* Has an owner, has an expiry date, and expiry date in the past? */
		if (tk->current_state.expires &&
				tk->current_state.owner &&
				now > tk->current_state.expires) {
			log_info("LOST ticket: \"%s\" no longer at %s",
					tk->name,
					ticket_owner_string(tk->current_state.owner));

			/* Couldn't renew in time - ticket lost. */
			tk->current_state.state = ST_INIT;
			tk->current_state.owner = NULL;
			ticket_write(tk);
		}

		/* Do we need to refresh? */
		if (tk->current_state.owner == local &&
				now + tk->expiry/2 > tk->current_state.expires) {
			log_info("RENEW ticket \"%s\"", tk->name);
			paxos_start_round(tk, local);

			/* TODO: remember when we started, and restart afresh after some retries */
		}

		/* Nothing to be done, until further notice. */
		if (!tk->current_state.owner)
			tk->next_cron = INT_MAX;

		break;

	case OP_PREPARING:
	case OP_PROPOSING:
		/* We ask others for a change; retry to get consensus. */
		ticket_broadcast_proposed_state(tk, tk->proposed_state.state);
		break;

	case OP_PROMISING:
	case OP_ACCEPTING:
	case OP_RECOVERY:
	case OP_REJECTED:
		break;

	default:
		break;
	}
}


void process_tickets(void)
{
	struct ticket_config *tk;
	int i;
	time_t now;

	time(&now);

	foreach_ticket(i, tk) {
		if (0)
		log_debug("ticket %s next cron %" PRIx64 ", now %" PRIx64 ", in %" PRIi64,
				tk->name, (uint64_t)tk->next_cron, (uint64_t)now,
				tk->next_cron - now);
		if (tk->next_cron > now)
			continue;

		log_debug("ticket cron: doing %s", tk->name);
		/* Set next value, cron may override. */
		tk->next_cron = now + tk->timeout;
		ticket_cron(tk);
	}
}



void tickets_log_info(void)
{
	struct ticket_config *tk;
	struct ticket_paxos_state *c, *p;
	int i;

	foreach_ticket(i, tk) {
		c = &tk->current_state;
		p = &tk->proposed_state;
		log_info("Ticket %s: state %s/%s "
				"mask %" PRIx64 "/%" PRIx64 " "
				"ballot %x/%x "
				"expires %-24.24s",
				tk->name,
				STATE_STRING(c->state),
				STATE_STRING(p->state),
				c->acknowledges, p->acknowledges,
				c->ballot,       p->ballot,
				ctime(&c->expires));
	}
}
