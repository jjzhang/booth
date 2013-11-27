/* 
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

#ifndef _INLINE_FN_H
#define _INLINE_FN_H

#include <time.h>
#include "config.h"
#include "transport.h"

static inline void init_header(struct boothc_header *h, int cmd,
			int result, int data_len)
{
	h->magic   = htonl(BOOTHC_MAGIC);
	h->version = htonl(BOOTHC_VERSION);
	h->length  = htonl(data_len);
	h->cmd     = htonl(cmd);
	h->from    = htonl(local->site_id);
	h->result  = htonl(result);
}

static inline void init_ticket_site_header(struct boothc_ticket_site_msg *msg, int cmd)
{
	init_header(&msg->header, cmd, 0, sizeof(*msg));
}

static inline void init_ticket_msg(struct boothc_ticket_msg *msg, int cmd)
{
	init_header(&msg->header, cmd, 0, sizeof(*msg));
	memset(&msg->ticket, 0, sizeof(msg->ticket));
}


static inline void init_ticket_site_msg(struct boothc_ticket_site_msg *msg, int cmd)
{
	init_ticket_site_header(msg, cmd);
	memset(&msg->site, 0, sizeof(msg->site));
	memset(&msg->ticket, 0, sizeof(msg->ticket));
}


static inline struct booth_transport const *transport(void) {
	return booth_transport + booth_conf->proto;
}


inline static uint32_t get_local_id(void)
{
	return local ? local->site_id : -1;
}


inline static uint32_t get_node_id(struct booth_site *node)
{
	return node ? node->site_id : NO_OWNER;
}


/** Returns number of seconds left, if any. */
inline static int owner_and_valid(const struct ticket_config *tk)
{
	int left;

	if (tk->current_state.owner != local)
		return 0;

	left = time(NULL) < tk->current_state.expires;
	return (left < 0) ? 0 : left;
}


#endif
