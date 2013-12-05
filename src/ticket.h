/* 
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
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

#ifndef _TICKET_H
#define _TICKET_H

#include "config.h"

#define DEFAULT_TICKET_EXPIRY	600
#define DEFAULT_TICKET_TIMEOUT	10

int check_ticket(char *ticket, struct ticket_config **tc);
int check_site(char *site, int *local);
int do_grant_ticket(struct ticket_config *ticket);
int revoke_ticket(struct ticket_config *ticket);
int list_ticket(char **pdata, unsigned int *len);

int message_recv(struct boothc_ticket_msg *msg, int msglen);
int setup_ticket(void);
int check_max_len_valid(const char *s, int max);

int do_grant_ticket(struct ticket_config *tk);
int do_revoke_ticket(struct ticket_config *tk);

int find_ticket_by_name(const char *ticket, struct ticket_config **found);
int find_ticket_by_handle(pl_handle_t handle, struct ticket_config **found);


/** @{
 * These functions do sanity checks, and prepare an answer
 * in the given msg place.
 * Sending is done by upper layers. 
 */
int ticket_answer_catchup(struct boothc_ticket_msg *msg);
/** @} */

int ticket_answer_list(int fd, struct boothc_ticket_msg *msg);
int ticket_answer_grant(int fd, struct boothc_ticket_msg *msg);
int ticket_answer_revoke(int fd, struct boothc_ticket_msg *msg);

int ticket_process_catchup(struct boothc_ticket_msg *msg, struct booth_site *sender);

void process_tickets(void);
void tickets_log_info(void);


#endif /* _TICKET_H */
