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
#include  <clplumbing/cl_random.h>
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
int test_external_prog(struct ticket_config *tk,
		int start_election)
{
	int rv;

	rv = run_handler(tk, tk->ext_verifier, 1);
	if (rv) {
		log_warn("we are not allowed to acquire ticket %s",
			tk->name);

		/* Give it to somebody else.
		 * Just send a VOTE_FOR message, so the
		 * others can start elections. */
		if (leader_and_valid(tk)) {
			disown_ticket(tk);
			if (start_election) {
				ticket_broadcast(tk, OP_VOTE_FOR, RLT_SUCCESS, OR_LOCAL_FAIL);
			}
		}
	}

	return rv;
}


/* Try to acquire a ticket
 * Could be manual grant or after ticket loss
 */
int acquire_ticket(struct ticket_config *tk, cmd_reason_t reason)
{
	if (test_external_prog(tk, 0))
		return RLT_EXT_FAILED;

	return new_election(tk, local, 1, reason);
}


/** Try to get the ticket for the local site.
 * */
int do_grant_ticket(struct ticket_config *tk, int options)
{
	int rv;

	if (tk->leader == local)
		return RLT_SUCCESS;
	if (is_owned(tk))
		return RLT_OVERGRANT;

	tk->delay_grant = time(NULL) +
			tk->term_duration + tk->acquire_after;

	if (options & OPT_IMMEDIATE) {
		log_warn("Grant ticket %s immediately! If there are "
				"unreachable sites, _hope_ you are sure that they don't "
				"have the ticket!",
				tk->name);
		tk->delay_grant = 0;
	}

	rv = acquire_ticket(tk, OR_ADMIN);
	return rv;
}


/** Ticket revoke.
 * Only to be started from the leader. */
int do_revoke_ticket(struct ticket_config *tk)
{
	log_info("revoking ticket %s", tk->name);

	reset_ticket(tk);
	ticket_write(tk);
	return ticket_broadcast(tk, OP_REVOKE, RLT_SUCCESS, OR_ADMIN);
}


int list_ticket(char **pdata, unsigned int *len)
{
	struct ticket_config *tk;
	char timeout_str[64];
	char pending_str[64];
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

		if (tk->delay_grant) {
			strcpy(pending_str, " (pending until ");
			strftime(pending_str + strlen(" (pending until "),
					sizeof(pending_str) - strlen(" (pending until ") - 1,
					"%F %T", localtime(&tk->delay_grant));
			strcat(pending_str, ")");
		} else
			*pending_str = '\0';

		cp += snprintf(cp,
				alloc - (cp - data),
				"ticket: %s, leader: %s, expires: %s, commit: %d%s\n",
				tk->name,
				ticket_leader_string(tk),
				timeout_str,
				tk->commit_index,
				pending_str);

		if (alloc - (cp - data) <= 0)
			return -ENOMEM;
	}

	*pdata = data;
	*len = cp - data;

	return 0;
}

void reset_ticket(struct ticket_config *tk)
{
	disown_ticket(tk);
	tk->state = ST_INIT;
	tk->voted_for = NULL;
}


int setup_ticket(void)
{
	struct ticket_config *tk;
	int i;

	foreach_ticket(i, tk) {
		reset_ticket(tk);

		if (local->type == SITE) {
			pcmk_handler.load_ticket(tk);
			if (time(NULL) >= tk->term_expires) {
				reset_ticket(tk);
				ticket_write(tk);
			}
		}


		/* if the ticket is uptodate and belongs to us, try with
		 * the heartbeat
		 */
		if (tk->is_granted && tk->leader == local) {
			if (!test_external_prog(tk, 1)) {
				tk->state = ST_LEADER;
				send_heartbeat(tk);
				ticket_activate_timeout(tk);
			}
		} else {
			/* otherwise, query status */
			ticket_broadcast(tk, OP_STATUS, RLT_SUCCESS, 0);
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

	init_header(&hdr, CMR_LIST, 0, RLT_SUCCESS, 0, sizeof(hdr) + olen);

	return send_header_plus(fd, &hdr, data, olen);
}


int ticket_answer_grant(int fd, struct boothc_ticket_msg *msg)
{
	int rv;
	struct ticket_config *tk;


	if (!check_ticket(msg->ticket.id, &tk)) {
		log_warn("client asked to grant unknown ticket %s",
				msg->ticket.id);
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	if (is_owned(tk)) {
		log_warn("client wants to grant an (already granted!) ticket %s",
				msg->ticket.id);
		rv = RLT_OVERGRANT;
		goto reply;
	}

	rv = do_grant_ticket(tk, ntohl(msg->header.options));

reply:
	init_header(&msg->header, CMR_GRANT, 0, rv ?: RLT_ASYNC, 0, sizeof(*msg));
	return send_ticket_msg(fd, msg);
}


int ticket_answer_revoke(int fd, struct boothc_ticket_msg *msg)
{
	int rv;
	struct ticket_config *tk;

	if (!check_ticket(msg->ticket.id, &tk)) {
		log_warn("client wants to revoke an unknown ticket %s",
				msg->ticket.id);
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	if (!is_owned(tk)) {
		log_info("client wants to revoke a free ticket %s",
				msg->ticket.id);
		/* Return a different result code? */
		rv = RLT_SUCCESS;
		goto reply;
	}

	if (tk->leader != local) {
		log_info("we do not own the ticket %s, "
				"redirect to leader %s",
				msg->ticket.id, ticket_leader_string(tk));
		rv = RLT_REDIRECT;
		goto reply;
	}

	rv = do_revoke_ticket(tk);
	if (rv == 0)
		rv = RLT_ASYNC;

reply:
	init_ticket_msg(msg, CMR_REVOKE, rv, 0, tk);
	return send_ticket_msg(fd, msg);
}


int ticket_broadcast(struct ticket_config *tk,
		cmd_request_t cmd, cmd_result_t res, cmd_reason_t reason)
{
	struct boothc_ticket_msg msg;

	init_ticket_msg(&msg, cmd, res, reason, tk);
	log_debug("broadcasting '%s' for ticket %s (term=%d, valid=%d)",
			state_to_string(cmd), tk->name,
			ntohl(msg.ticket.term),
			ntohl(msg.ticket.term_valid_for));

	return transport()->broadcast(&msg, sizeof(msg));
}


int new_round(struct ticket_config *tk, cmd_reason_t reason)
{
	int rv = 0;
	struct timespec delay;

	disown_ticket(tk);

	/* New vote round; §5.2 */
	if (local->type == SITE) {
		/* delay the next election start for up to 200ms */
		delay.tv_sec = 0;
		delay.tv_nsec = 1000000L * (long)cl_rand_from_interval(0, 200);
		nanosleep(&delay, NULL);

		rv = new_election(tk, NULL, 1, reason);
		ticket_write(tk);
	}

	return rv;
}


static void ticket_cron(struct ticket_config *tk)
{
	time_t now;
	int ack_cnt;
	struct booth_site *new_leader;

	now = time(NULL);


	R(tk);
	/* Has an owner, has an expiry date, and expiry date in the past?
	 * Losing the ticket must happen in _every_ state. */
	if (tk->term_expires &&
			is_owned(tk) &&
			now >= tk->term_expires) {

		log_warn("LOST ticket: %s no longer at %s",
				tk->name,
				ticket_leader_string(tk));

		/* Couldn't renew in time - ticket lost. */
		new_round(tk, OR_TKT_LOST);
		return;
	}
	R(tk);

	switch(tk->state) {
	case ST_INIT:
		/* init state, nothing to do */
		break;

	case ST_FOLLOWER:
		/* nothing here either, ticket loss is caught earlier
		 * */
		break;

	case ST_CANDIDATE:
		/* §5.2 */
		/* not everybody answered, but if we have majority... */
		new_leader = majority_votes(tk);
		if (new_leader) {
			leader_elected(tk, new_leader);
		} else if (now > tk->election_end) {
			/* This is previous election timed out */
			new_election(tk, NULL, 0, OR_AGAIN);
		}
		break;

	case ST_LEADER:
		/* we get here after we broadcasted a heartbeat;
		 * by this time all sites should've acked the heartbeat
		 */
		if (tk->acks_expected) {
			tk->retry_number ++;
			if (!majority_of_bits(tk, tk->acks_received)) {
				ack_cnt = count_bits(tk->acks_received) - 1;
				if (!ack_cnt) {
					log_warn("no answers to heartbeat for ticket %s on try #%d, "
					"we are alone",
					tk->name,
					tk->retry_number);
				} else {
					log_warn("not enough answers to heartbeat for ticket %s on try #%d: "
					"only got %d answers",
					tk->name,
					tk->retry_number,
					ack_cnt);
				}
			/* Don't give up, though - there's still some time until leadership is lost. */
			} else {
				/* we have the majority, update the ticket, at
				 * least the local copy if we're still not
				 * allowed to commit
				 */
				leader_update_ticket(tk);
			}
		} else {
			/* this is ticket renewal, check what the
			 * external test says */
			if (test_external_prog(tk, 1))
				return;
		}

		send_heartbeat(tk);
		if (tk->retry_number < tk->retries) {
			ticket_activate_timeout(tk);
		} else {
			set_ticket_wakeup(tk);
		}
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
				"leader %s "
				"expires %-24.24s",
				tk->name,
				state_to_string(tk->state),
				tk->commit_index,
				ticket_leader_string(tk),
				ctime(&tk->term_expires));
	}
}


static void update_acks(
		struct ticket_config *tk,
		struct booth_site *sender,
		struct booth_site *leader,
		struct boothc_ticket_msg *msg
	       )
{
	uint32_t cmd;

	cmd = ntohl(msg->header.cmd);
	if (tk->acks_expected != cmd)
		return;

	/* got an ack! */
	tk->acks_received |= sender->bitmask;

	log_debug("got ACK from %s, %d/%d agree.",
			site_string(sender),
			count_bits(tk->acks_received),
			booth_conf->site_count);

	if (all_replied(tk)) {
		tk->acks_expected = 0;
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
		log_warn("got invalid ticket name %s from %s",
				msg->ticket.id, site_string(source));
		return -EINVAL;
	}


	leader_u = ntohl(msg->ticket.leader);
	if (!find_site_by_id(leader_u, &leader)) {
		log_error("Message with unknown owner %u received", leader_u);
		return -EINVAL;
	}

	update_acks(tk, source, leader, msg);

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
		/* If there is (or should be) some owner, check on it later on.
		 * If no one is interested - don't care. */
		if (is_owned(tk) &&
				(local->type == SITE))
			ticket_next_cron_at_coarse(tk,
					tk->term_expires + tk->acquire_after);
		break;

	default:
		log_error("unknown ticket state: %d", tk->state);
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


	init_ticket_msg(&msg, OP_REJECTED, code, 0, tk);
	return booth_udp_send(dest, &msg, sizeof(msg));
}
