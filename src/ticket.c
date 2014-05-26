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


int ticket_write(struct ticket_config *tk)
{
	if (local->type != SITE)
		return -EINVAL;

	if (tk->leader == local) {
		pcmk_handler.grant_ticket(tk);
	} else {
		pcmk_handler.revoke_ticket(tk);
	}
	tk->update_cib = 0;

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
		tk_log_warn("we are not allowed to acquire ticket");

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

	tk_log_info("granting ticket");

	if (tk->leader == local)
		return RLT_SUCCESS;
	if (is_owned(tk))
		return RLT_OVERGRANT;

	tk->delay_commit = time(NULL) +
			tk->term_duration + tk->acquire_after;

	if (options & OPT_IMMEDIATE) {
		tk_log_warn("granting ticket immediately! If there are "
				"unreachable sites, _hope_ you are sure that they don't "
				"have the ticket!");
		tk->delay_commit = 0;
	}

	rv = acquire_ticket(tk, OR_ADMIN);
	if (rv)
		tk->delay_commit = 0;
	return rv;
}


/** Ticket revoke.
 * Only to be started from the leader. */
int do_revoke_ticket(struct ticket_config *tk)
{
	tk_log_info("revoking ticket");

	reset_ticket(tk);
	tk->leader = no_leader;
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

		if (tk->leader == local && tk->delay_commit > time(NULL)) {
			strcpy(pending_str, " (commit pending until ");
			strftime(pending_str + strlen(" (commit pending until "),
					sizeof(pending_str) - strlen(" (commit pending until ") - 1,
					"%F %T", localtime(&tk->delay_commit));
			strcat(pending_str, ")");
		} else
			*pending_str = '\0';

		cp += snprintf(cp,
				alloc - (cp - data),
				"ticket: %s, leader: %s",
				tk->name,
				ticket_leader_string(tk));

		if (is_owned(tk)) {
			cp += snprintf(cp,
					alloc - (cp - data),
					", expires: %s, commit: %d%s\n",
					timeout_str,
					tk->commit_index,
					pending_str);
		} else {
			cp += snprintf(cp, alloc - (cp - data), "\n");
		}

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


static void reacquire_ticket(struct ticket_config *tk)
{
	int valid;
	const char *where_granted = "\0";
	char buff[64];

	valid = (tk->term_expires >= time(NULL));

	if (tk->is_granted || tk->leader == local) {
		where_granted = "granted here";
	} else {
		snprintf(buff, sizeof(buff), "granted to %s",
			site_string(tk->leader));
		where_granted = buff;
	}

	if (!valid) {
		tk_log_warn("%s, but not valid "
			"anymore (will try to reacquire)", where_granted);
	}
	if (tk->is_granted && tk->leader != local) {
		if (tk->leader && tk->leader != no_leader) {
			tk_log_error("granted here, but also %s, "
				"that's really too bad (will try to reacquire)",
				where_granted);
		} else {
			tk_log_warn("granted here, but we're "
				"not recorded as the grantee (will try to reacquire)");
		}
	}

	/* try to acquire the
	 * ticket through new elections
	 */
	acquire_ticket(tk, OR_REACQUIRE);
}

void update_ticket_state(struct ticket_config *tk, struct booth_site *sender)
{
	if (tk->leader == local || tk->is_granted) {
		/* message from a live leader with valid ticket? */
		if (sender == tk->leader && term_time_left(tk)) {
			tk_log_info("ticket was granted here, "
					"but it's live at %s (revoking here)",
					site_string(sender));
			ticket_write(tk);
			tk->state = ST_FOLLOWER;
			tk->next_state = ST_FOLLOWER;
		} else {
			tk->next_state = ST_LEADER;
		}
	} else {
		if (!tk->leader || tk->leader == no_leader) {
			if (sender)
				tk_log_info("ticket is not granted");
			else
				tk_log_info("ticket is not granted (from CIB)");
			tk->state = ST_INIT;
		} else {
			if (sender)
				tk_log_info("ticket granted to %s (says %s)",
					site_string(tk->leader),
					site_string(sender));
			else
				tk_log_info("ticket granted to %s (from CIB)",
					site_string(tk->leader));
			tk->state = ST_FOLLOWER;
			/* just make sure that we check the ticket soon */
			tk->next_state = ST_FOLLOWER;
		}
	}
}

int setup_ticket(void)
{
	struct ticket_config *tk;
	int i;

	foreach_ticket(i, tk) {
		reset_ticket(tk);

		if (local->type == SITE) {
			if (!pcmk_handler.load_ticket(tk)) {
				update_ticket_state(tk, NULL);
			}
			tk->update_cib = 1;
		}

		tk_log_info("broadcasting state query");
		/* wait until all send their status (or the first
		 * timeout) */
		tk->start_postpone = 1;
		expect_replies(tk, OP_MY_INDEX);
		ticket_broadcast(tk, OP_STATUS, RLT_SUCCESS, 0);
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
		rv = RLT_TICKET_IDLE;
		goto reply;
	}

	if (tk->leader != local) {
		log_info("the ticket %s is not granted here, "
				"redirect to %s",
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
	tk_log_debug("broadcasting '%s' (term=%d, valid=%d)",
			state_to_string(cmd),
			ntohl(msg.ticket.term),
			ntohl(msg.ticket.term_valid_for));

	return transport()->broadcast(&msg, sizeof(msg));
}


/* is it safe to commit the grant?
 * if we didn't hear from all sites on the initial grant, we may
 * need to delay the commit
 *
 * TODO: investigate possibility to devise from history whether a
 * missing site could be holding a ticket or not
 */
static int ticket_dangerous(struct ticket_config *tk)
{
	if (!tk->delay_commit)
		return 0;

	if (tk->delay_commit <= time(NULL) ||
			all_sites_replied(tk)) {
		tk_log_debug("ticket delay commit expired");
		tk->delay_commit = 0;
		return 0;
	} else {
		tk_log_debug("delay ticket commit for %ds",
				(int)(tk->delay_commit - time(NULL)));
	}

	return 1;
}


/* update the ticket on the leader, write it to the CIB, and
   send out the update message to others with the new expiry
   time
*/
int leader_update_ticket(struct ticket_config *tk)
{
	struct boothc_ticket_msg msg;
	int rv = 0;

	if (tk->ticket_updated >= 2)
		return 0;

	if (tk->ticket_updated < 1) {
		tk->ticket_updated = 1;
		tk->term_expires = time(NULL) + tk->term_duration;

		tk_log_debug("broadcasting ticket update");
		init_ticket_msg(&msg, OP_UPDATE, RLT_SUCCESS, 0, tk);
		rv = transport()->broadcast(&msg, sizeof(msg));
	}

	if (tk->ticket_updated < 2) {
		if (!ticket_dangerous(tk)) {
			tk->ticket_updated = 2;
			ticket_write(tk);
		} else {
			/* log just once, on the first retry */
			if (tk->retry_number == 1)
				tk_log_info("delaying ticket commit to CIB for %ds "
					"(or all sites are reached)",
					(int)(tk->delay_commit - time(NULL)));
		}
	}

	return rv;
}


static void log_lost_servers(struct ticket_config *tk)
{
	struct booth_site *n;
	int i;

	if (tk->retry_number > 1)
		/* log those that we couldn't reach, but do
		 * that only on the first retry
		 */
		return;

	for (i = 0; i < booth_conf->site_count; i++) {
		n = booth_conf->site + i;
		if (!(tk->acks_received & n->bitmask)) {
			tk_log_warn("%s %s didn't acknowledge our request, "
			"will retry %d times",
			(n->type == ARBITRATOR ? "arbitrator" : "site"),
			site_string(n),
			tk->retries);
		}
	}
}

static void resend_msg(struct ticket_config *tk)
{
	struct booth_site *n;
	int i;

	if (!(tk->acks_received ^ local->bitmask)) {
		ticket_broadcast(tk, tk->acks_expected, RLT_SUCCESS, 0);
	} else {
		for (i = 0; i < booth_conf->site_count; i++) {
			n = booth_conf->site + i;
			if (!(tk->acks_received & n->bitmask)) {
				tk_log_debug("resending %s to %s",
						state_to_string(tk->acks_expected),
						site_string(n)
						);
				send_msg(tk->acks_expected, tk, n);
			}
		}
	}
}

static void handle_resends(struct ticket_config *tk)
{
	int ack_cnt;

	if (++tk->retry_number > tk->retries) {
		tk_log_debug("giving up on sending retries");
		no_resends(tk);
		set_ticket_wakeup(tk);
		return;
	}

	if (!majority_of_bits(tk, tk->acks_received)) {
		ack_cnt = count_bits(tk->acks_received) - 1;
		if (!ack_cnt) {
			tk_log_warn("no answers to heartbeat (try #%d), "
			"we are alone",
			tk->retry_number);
		} else {
			tk_log_warn("not enough answers to heartbeat (try #%d): "
			"only got %d answers",
			tk->retry_number,
			ack_cnt);
		}
	} else {
		log_lost_servers(tk);
		/* we have the majority, update the ticket, at
		 * least the local copy if we're still not
		 * allowed to commit
		 */
		leader_update_ticket(tk);
	}

	resend_msg(tk);
	ticket_activate_timeout(tk);
}

int postpone_ticket_processing(struct ticket_config *tk)
{
	extern time_t start_time;

	return tk->start_postpone &&
		((time(NULL) - start_time) < tk->timeout);
}

static void ticket_cron(struct ticket_config *tk)
{
	time_t now;

	now = time(NULL);

	/* don't process the tickets too early */
	if (postpone_ticket_processing(tk)) {
		tk_log_debug("ticket processing postponed (start_postpone=%d)",
				tk->start_postpone);
		/* but run again soon */
		ticket_activate_timeout(tk);
		return;
	}

	if (tk->acks_expected == OP_MY_INDEX) {
		no_resends(tk);
	}

	if (tk->next_state) {
		if (tk->next_state == ST_LEADER) {
			if (tk->state == ST_LEADER) {
				new_round(tk, OR_SPLIT);
			} else {
				reacquire_ticket(tk);
			}
		}
		tk->next_state = 0;
		tk->start_postpone = 0;
		goto out;
	}

	/* Has an owner, has an expiry date, and expiry date in the past?
	 * Losing the ticket must happen in _every_ state. */
	if (tk->term_expires &&
			is_owned(tk) &&
			now >= tk->term_expires) {

		if (tk->leader != local) {
			tk_log_warn("lost at %s", site_string(tk->leader));
		} else {
			tk_log_warn("lost majority (revoking locally)");
		}

		tk->lost_leader = tk->leader;
		tk->next_state = 0;
		/* Couldn't renew in time - ticket lost. */
		new_round(tk, OR_TKT_LOST);
		return;
	}

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
		elections_end(tk);
		break;

	case ST_LEADER:
		/* timeout or ticket renewal? */
		if (tk->acks_expected) {
			handle_resends(tk);
		} else {
			/* this is ticket renewal, run local test */
			if (!test_external_prog(tk, 1)) {
				send_heartbeat(tk);
				ticket_activate_timeout(tk);
			}
		}
		break;

	default:
		break;
	}

out:
	if (tk->update_cib)
		ticket_write(tk);
}


void process_tickets(void)
{
	struct ticket_config *tk;
	int i;
	struct timeval now, last_cron;
	float sec_until;

	gettimeofday(&now, NULL);

	foreach_ticket(i, tk) {
		sec_until = timeval_to_float(tk->next_cron) - timeval_to_float(now);
		if (0)
			tk_log_debug("next cron %" PRIx64 ".%03d, "
					"now %" PRIx64 "%03d, in %f",
					(uint64_t)tk->next_cron.tv_sec, timeval_msec(tk->next_cron),
					(uint64_t)now.tv_sec, timeval_msec(now),
					sec_until);
		if (sec_until > 0.0)
			continue;

		tk_log_debug("ticket cron");


		last_cron = tk->next_cron;
		ticket_cron(tk);
		if (!timercmp(&last_cron, &tk->next_cron, !=)) {
			tk_log_debug("nobody set ticket wakeup");
			set_ticket_wakeup(tk);
		}
	}
}



void tickets_log_info(void)
{
	struct ticket_config *tk;
	int i;

	foreach_ticket(i, tk) {
		tk_log_info("state '%s' "
				"term %d "
				"commit index %d "
				"leader %s "
				"expires %-24.24s",
				state_to_string(tk->state),
				tk->current_term,
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
	if (tk->acks_expected != cmd &&
			tk->acks_expected != OP_REJECTED)
		return;

	/* got an ack! */
	tk->acks_received |= sender->bitmask;

	tk_log_debug("got ACK from %s, %d/%d agree.",
			site_string(sender),
			count_bits(tk->acks_received),
			booth_conf->site_count);

	if (tk->delay_commit && all_sites_replied(tk)) {
		tk->delay_commit = 0;
	}

	if (all_replied(tk)) {
		no_resends(tk);
		tk->start_postpone = 0;
		set_ticket_wakeup(tk);
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
		tk_log_error("message with unknown leader %u received", leader_u);
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
	gettimeofday(&now, NULL);

	switch (tk->state) {
	case ST_LEADER:
		assert(tk->leader == local);

		tv = now;
		tv.tv_sec = next_vote_starts_at(tk);

		/* If timestamp is in the past, wakeup at the expiry
		 * time. */
		if (timeval_compare(tv, now) <= 0) {
			tk_log_debug("next ts in the past (%f)",
				timeval_to_float(tv) - timeval_to_float(now));
			tv.tv_sec = tk->term_expires;
		}

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
		tk_log_error("unknown ticket state: %d", tk->state);
	}

	if (tk->next_state) {
		/* we need to do something soon here */
		ticket_activate_timeout(tk);
	}

	if (ANYDEBUG) {
		float sec_until;
		gettimeofday(&now, NULL);
		sec_until = timeval_to_float(tk->next_cron) - timeval_to_float(now);
		tk_log_debug("set ticket wakeup in %f", sec_until);
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

int send_msg (
		int cmd,
		struct ticket_config *tk,
		struct booth_site *dest
	       )
{
	struct boothc_ticket_msg msg;

	if (cmd == OP_MY_INDEX) {
		tk_log_info("sending status to %s",
				site_string(dest));
	}
	init_ticket_msg(&msg, cmd, RLT_SUCCESS, 0, tk);
	return booth_udp_send(dest, &msg, sizeof(msg));
}
