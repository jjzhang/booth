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
#include "transport.h"



inline static uint32_t get_local_id(void)
{
	return local ? local->site_id : -1;
}


inline static uint32_t get_node_id(struct booth_site *node)
{
	return node ? node->site_id : NO_OWNER;
}


inline static int ticket_valid_for(const struct ticket_config *tk)
{
	int left;

	left = tk->expires - time(NULL);
	return (left < 0) ? 0 : left;
}


/** Returns number of seconds left, if any. */
inline static int owner_and_valid(const struct ticket_config *tk)
{
	if (tk->owner != local)
		return 0;

	return ticket_valid_for(tk);
}

static inline void init_header_bare(struct boothc_header *h) {
	h->magic   = htonl(BOOTHC_MAGIC);
	h->version = htonl(BOOTHC_VERSION);
	h->from    = htonl(local->site_id);
	h->iv      = htonl(0);
	h->auth1   = htonl(0);
	h->auth2   = htonl(0);
}

static inline void init_header(struct boothc_header *h, int cmd,
			int result, int data_len)
{
	init_header_bare(h);
	h->length  = htonl(data_len);
	h->cmd     = htonl(cmd);
	h->result  = htonl(result);
}

static inline void init_ticket_site_header(struct boothc_ticket_msg *msg, int cmd)
{
	init_header(&msg->header, cmd, 0, sizeof(*msg));
}

static inline void init_ticket_msg(struct boothc_ticket_msg *msg,
		int cmd, int rv,
		struct ticket_config *tk)
{
	assert(sizeof(msg->ticket.id) == sizeof(tk->name));

	init_header(&msg->header, cmd, rv, sizeof(*msg));

	if (!tk) {
		memset(&msg->ticket, 0, sizeof(msg->ticket));
	} else {
		memcpy(msg->ticket.id, tk->name, sizeof(msg->ticket.id));

		msg->ticket.expiry      = htonl(ticket_valid_for(tk));
		msg->ticket.owner       = htonl(get_node_id(tk->owner));
		msg->ticket.ballot      = htonl(tk->new_ballot);
		msg->ticket.prev_ballot = htonl(tk->last_ack_ballot);
	}
}


static inline struct booth_transport const *transport(void)
{
	return booth_transport + booth_conf->proto;
}


static inline const char *ticket_owner_string(struct booth_site *site)
{
	return site ? site->addr_string : "NONE";
}


static inline void disown_ticket(struct ticket_config *tk)
{
	tk->owner = NULL;
	tk->proposed_owner = NULL;
	time(&tk->expires);
}

static inline void disown_if_expired(struct ticket_config *tk)
{
	if (time(NULL) >= tk->expires || !tk->proposed_owner)
		disown_ticket(tk);
}


static inline int all_agree(struct ticket_config *tk)
{
	return tk->proposal_acknowledges == booth_conf->site_bits;
}

static inline int majority_agree(struct ticket_config *tk)
{
	/* Use ">" to get majority decision, even for an even number
	 * of participants. */
	return __builtin_popcount(tk->proposal_acknowledges) * 2 >
			booth_conf->site_count;
}




/* We allow half of the uint32_t to be used;
 * half of that below, half of that above the current known "good" value.
 *   0                                                     UINT32_MAX
 *   |--------------------------+----------------+------------|
 *                              |        |       |
 *                              |--------+-------| allowed range
 *                                       |
 *                                       current ballot
 *
 * So, on overflow it looks like that:
 *                                UINT32_MAX  0
 *   |--------------------------+-----------||---+------------|
 *                              |        |       |
 *                              |--------+-------| allowed range
 *                                       |
 *                                       current ballot
 *
 * This should be possible by using the same datatype and relying
 * on the under/overflow semantics.
 *
 *
 * Having 30 bits available, and assuming an expire time of
 * one minute and a (high) ballot step of 64 == 2^6 (because
 * of weights), we get 2^24 minutes of range - which is ~750
 * years. "Should be enough for everybody."
 */
static inline int ballot_is_higher_than(uint32_t b_high, uint32_t b_low)
{
	uint32_t diff;

	if (b_high == b_low)
		return 0;

	diff = b_high - b_low;
	if (diff < UINT32_MAX/4)
		return 1;

	diff = b_low - b_high;
	if (diff < UINT32_MAX/4)
		return 0;

	assert(!"ballot out of range - invalid");
}


static inline uint32_t ballot_max2(uint32_t a, uint32_t b)
{
	return ballot_is_higher_than(a, b) ? a : b;
}

static inline uint32_t ballot_max3(uint32_t a, uint32_t b, uint32_t c)
{
	return ballot_max2( ballot_max2(a, b), c);
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


static inline time_t next_renewal_starts_at(struct ticket_config *tk)
{
	time_t half_exp, retries_needed;

	/* If not owner, don't renew. */
	if (tk->owner != local)
		return 0;

	/* Try to renew at half of expiry time. */
	half_exp = tk->expires - tk->expiry/2;
	/* Also start renewal if we couldn't get
	 * a few message retransmission in the alloted
	 * expiry time. */
	retries_needed = tk->expires - tk->timeout * tk->retries/2;

	/* Return earlier timestamp. */
	return half_exp < retries_needed
		? half_exp
		: retries_needed;
}


static inline int should_start_renewal(struct ticket_config *tk)
{
	time_t now, when;

	when = next_renewal_starts_at(tk);
	if (!when)
		return 0;

	time(&now);
	return when <= now;
}


#endif
