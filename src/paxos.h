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

#ifndef _PAXOS_H
#define _PAXOS_H

#include "config.h"
#include "ticket.h"


#define PROPOSER	0x4
#define ACCEPTOR	0x2
#define LEARNER		0x1


int paxos_answer(
		struct ticket_config *tk,
		struct booth_site *from,
		struct boothc_ticket_msg *msg,
		uint32_t ballot,
		struct booth_site *new_owner_p);

int paxos_start_round(struct ticket_config *tk, struct booth_site *new_owner);
void abort_proposal(struct ticket_config *tk);

#endif /* _PAXOS_H */
