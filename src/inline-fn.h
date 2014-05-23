/* 
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

#ifndef _INLINE_FN_H
#define _INLINE_FN_H

#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include "config.h"
#include "ticket.h"
#include "transport.h"



inline static uint32_t get_local_id(void)
{
	return local ? local->site_id : -1;
}


inline static uint32_t get_node_id(struct booth_site *node)
{
	return node ? node->site_id : NO_ONE;
}


inline static int term_time_left(const struct ticket_config *tk)
{
	int left;

	left = tk->term_expires - time(NULL);
	return (left < 0) ? 0 : left;
}


/** Returns number of seconds left, if any. */
inline static int leader_and_valid(const struct ticket_config *tk)
{
	if (tk->leader != local)
		return 0;

	return term_time_left(tk);
}


/** Is this some leader? */
inline static int is_owned(const struct ticket_config *tk)
{
	return (tk->leader && tk->leader != no_leader);
}


static inline void init_header_bare(struct boothc_header *h) {
	h->magic   = htonl(BOOTHC_MAGIC);
	h->version = htonl(BOOTHC_VERSION);
	h->from    = htonl(local->site_id);
	h->iv      = htonl(0);
	h->auth1   = htonl(0);
	h->auth2   = htonl(0);
}

static inline void init_header(struct boothc_header *h,
			int cmd, int options,
			int result, int reason, int data_len)
{
	init_header_bare(h);
	h->length  = htonl(data_len);
	h->cmd     = htonl(cmd);
	h->options = htonl(options);
	h->result  = htonl(result);
	h->reason  = htonl(reason);
}

static inline void init_ticket_site_header(struct boothc_ticket_msg *msg, int cmd)
{
	init_header(&msg->header, cmd, 0, 0, 0, sizeof(*msg));
}

static inline void init_ticket_msg(struct boothc_ticket_msg *msg,
		int cmd, int rv, int reason,
		struct ticket_config *tk)
{
	assert(sizeof(msg->ticket.id) == sizeof(tk->name));

	init_header(&msg->header, cmd, 0, rv, reason, sizeof(*msg));

	if (!tk) {
		memset(&msg->ticket, 0, sizeof(msg->ticket));
	} else {
		memcpy(msg->ticket.id, tk->name, sizeof(msg->ticket.id));

		msg->ticket.leader         = htonl(get_node_id(
			(tk->leader && tk->leader != no_leader) ? tk->leader : tk->voted_for));
		msg->ticket.term           = htonl(tk->current_term);
		msg->ticket.term_valid_for = htonl(term_time_left(tk));

		msg->ticket.leader_commit  = htonl(tk->commit_index);
	}
}


static inline struct booth_transport const *transport(void)
{
	return booth_transport + booth_conf->proto;
}


static inline const char *site_string(struct booth_site *site)
{
	return site ? site->addr_string : "NONE";
}


static inline const char *ticket_leader_string(struct ticket_config *tk)
{
	return site_string(tk->leader);
}


static inline void disown_ticket(struct ticket_config *tk)
{
	tk->leader = NULL;
	tk->is_granted = 0;
	time(&tk->term_expires);
}

static inline int disown_if_expired(struct ticket_config *tk)
{
	if (time(NULL) >= tk->term_expires ||
			!tk->leader) {
		disown_ticket(tk);
		return 1;
	}

	return 0;
}



/* We allow half of the uint32_t to be used;
 * half of that below, half of that above the current known "good" value.
 *   0                                                     UINT32_MAX
 *   |--------------------------+----------------+------------|
 *                              |        |       |
 *                              |--------+-------| allowed range
 *                                       |
 *                                       current commit index
 *
 * So, on overflow it looks like that:
 *                                UINT32_MAX  0
 *   |--------------------------+-----------||---+------------|
 *                              |        |       |
 *                              |--------+-------| allowed range
 *                                       |
 *                                       current commit index
 *
 * This should be possible by using the same datatype and relying
 * on the under/overflow semantics.
 *
 *
 * Having 30 bits available, and assuming an expire time of
 * one minute and a (high) commit index step of 64 == 2^6 (because
 * of weights), we get 2^24 minutes of range - which is ~750
 * years. "Should be enough for everybody."
 */
static inline int index_is_higher_than(uint32_t c_high, uint32_t c_low)
{
	uint32_t diff;

	if (c_high == c_low)
		return 0;

	diff = c_high - c_low;
	if (diff < UINT32_MAX/4)
		return 1;

	diff = c_low - c_high;
	if (diff < UINT32_MAX/4)
		return 0;

	assert(!"commit index out of range - invalid");
}


static inline uint32_t index_max2(uint32_t a, uint32_t b)
{
	return index_is_higher_than(a, b) ? a : b;
}

static inline uint32_t index_max3(uint32_t a, uint32_t b, uint32_t c)
{
	return index_max2( index_max2(a, b), c);
}


static inline double timeval_to_float(struct timeval tv)
{
	return tv.tv_sec + tv.tv_usec*(double)1.0e-6;
}

static inline int timeval_msec(struct timeval tv)
{
	int m;

	m = tv.tv_usec / 1000;
	if (m >= 1000)
		m = 999;
	return m;
}


static inline int timeval_compare(struct timeval tv1, struct timeval tv2)
{
	if (tv1.tv_sec < tv2.tv_sec)
		return -1;
	if (tv1.tv_sec > tv2.tv_sec)
		return +1;
	if (tv1.tv_usec < tv2.tv_usec)
		return -1;
	if (tv1.tv_usec > tv2.tv_usec)
		return +1;
	return 0;
}


static inline int timeval_in_past(struct timeval which)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return timeval_compare(tv, which) > 0;
}


static inline time_t next_vote_starts_at(struct ticket_config *tk)
{
	time_t half_exp, retries_needed, t;

	/* If not owner, don't renew. */
	if (tk->leader != local)
		return 0;

	/* Try to renew at half of expiry time. */
	half_exp = tk->term_expires - tk->term_duration/2;
	/* Also start renewal if we couldn't get
	 * a few message retransmission in the alloted
	 * expiry time. */
	retries_needed = tk->term_expires - tk->timeout * tk->retries/2;

	/* Return earlier timestamp. */
	t = min(half_exp, retries_needed);

	return t;
}


static inline int should_start_renewal(struct ticket_config *tk)
{
	time_t now, when;

	when = next_vote_starts_at(tk);
	if (!when)
		return 0;

	time(&now);
	return when <= now;
}

static inline void expect_replies(struct ticket_config *tk,
		int reply_type)
{
	tk->retry_number = 0;
	tk->acks_expected = reply_type;
	tk->acks_received = local->bitmask;
	tk->req_sent_at  = time(NULL);
	tk->ticket_updated = 0;
}

static inline void no_resends(struct ticket_config *tk)
{
	tk->retry_number = 0;
	tk->acks_expected = 0;
	tk->acks_received = 0;
}

static inline int send_heartbeat(struct ticket_config *tk)
{
	expect_replies(tk, OP_HEARTBEAT);

	return ticket_broadcast(tk, OP_HEARTBEAT, RLT_SUCCESS, 0);
}

static inline struct booth_site *my_vote(struct ticket_config *tk)
{
	return tk->votes_for[ local->index ];
}


static inline int count_bits(uint64_t val) {
	return __builtin_popcount(val);
}

static inline int majority_of_bits(struct ticket_config *tk, uint64_t val)
{
	/* Use ">" to get majority decision, even for an even number
	 * of participants. */
	return count_bits(val) * 2 >
		booth_conf->site_count;
}


static inline int all_replied(struct ticket_config *tk)
{
	return !(tk->acks_received ^ booth_conf->all_bits);
}

static inline int all_sites_replied(struct ticket_config *tk)
{
	return !((tk->acks_received & booth_conf->sites_bits) ^ booth_conf->sites_bits);
}


#endif
