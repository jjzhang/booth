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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "ticket.h"
#include "config.h"
#include "pacemaker.h"
#include "list.h"
#include "log.h"
#include "paxos_lease.h"
#include "paxos.h"

#define PAXOS_MAGIC     0xDB12
#define TK_LINE		256

struct booth_msghdr {
        uint16_t magic;
        uint16_t checksum;
        uint32_t len;
} __attribute__((packed));

struct ticket {
	char id[BOOTH_NAME_LEN+1];
	pl_handle_t handle;
	int owner;
	int expiry;
	unsigned long long expires;
	struct list_head list;
};

static LIST_HEAD(ticket_list);

static unsigned char *role;

int check_ticket(char *ticket)
{
	int i;

	if (!booth_conf)
		return 0;

	for (i = 0; i < booth_conf->ticket_count; i++) {
		if (!strcmp(booth_conf->ticket[i].name, ticket))
			return 1;
	}

	return 0;
}

int check_site(char *site, int *local)
{
	int i;

	if (!booth_conf)
		return 0;

	for (i = 0; i < booth_conf->node_count; i++) {
		if (booth_conf->node[i].type == SITE
		    && !strcmp(booth_conf->node[i].addr, site)) {
			*local = booth_conf->node[i].local;
			return 1;
		}
	}

	return 0;
}

static int * ticket_priority(int i)
{
	int j;

	/* TODO: need more precise check */
	for (j = 0; j < booth_conf->node_count; j++) {
		if (booth_conf->ticket[i].weight[j] == 0)
			return NULL;
	}
	return booth_conf->ticket[i].weight;
}

static int ticket_get_myid(void)
{
	return booth_transport[booth_conf->proto].get_myid();
}

static void end_acquire(pl_handle_t handle, int result)
{
	struct ticket *tk;
	int found = 0;

	if (result == 0) {
		list_for_each_entry(tk, &ticket_list, list) {
			if (tk->handle == handle) {
				tk->owner = ticket_get_myid();
				found = 1;
				break;
			}
		}
		if (!found)
			log_error("BUG: ticket handle %d does not exist",
				  handle);
		log_info("ticket %s acquired", tk->id);
		log_info("ticket %s granted to local (id %d)", tk->id,
			 ticket_get_myid());
	}
}

static int ticket_send(unsigned long id, void *value, int len)
{
	int i, rv = -1;
	struct booth_node *to = NULL;
	struct booth_msghdr *hdr;
	void *buf;

	for (i = 0; i < booth_conf->node_count; i++) {
		if (booth_conf->node[i].nodeid == id)
			to = &booth_conf->node[i];
	}
	if (!to)
		return rv;

	buf = malloc(sizeof(struct booth_msghdr) + len);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, sizeof(struct booth_msghdr) + len);
	hdr = buf;
	hdr->magic = htons(PAXOS_MAGIC);
	hdr->len = htonl(sizeof(struct booth_msghdr) + len);
	memcpy((char *)buf + sizeof(struct booth_msghdr), value, len);

	rv = booth_transport[booth_conf->proto].send(
		(unsigned long)to, buf, sizeof(struct booth_msghdr) + len);

	free(buf);
	return rv;
}

static int ticket_broadcast(void *value, int len)
{
	void *buf;
	struct booth_msghdr *hdr;
	int rv;

	buf = malloc(sizeof(struct booth_msghdr) + len);
	if (!buf)
		return -ENOMEM;
	memset(buf, 0, sizeof(struct booth_msghdr) + len);
	hdr = buf;
	hdr->magic = htons(PAXOS_MAGIC);
	hdr->len = htonl(sizeof(struct booth_msghdr) + len);
	memcpy((char *)buf + sizeof(struct booth_msghdr), value, len);

	rv = booth_transport[booth_conf->proto].broadcast(
			buf, sizeof(struct booth_msghdr) + len);

	free(buf);
	return rv;	
}

static int ticket_read(const void *name, int *owner, 
		       unsigned long long *expires)
{
	struct ticket *tk;
	int found = 0;
	
	list_for_each_entry(tk, &ticket_list, list) {
		if (!strcmp(tk->id, name)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("BUG: ticket_read failed (ticket %s does not exist)",
			  (char *)name);
		return -1;
	}

	pcmk_handler.load_ticket(tk->id, &tk->owner, &tk->expires);
	*owner = tk->owner;
	*expires = tk->expires;
 
	return 0;
}

static int ticket_write(pl_handle_t handle, struct paxos_lease_result *result)
{
	struct ticket *tk;
	int found = 0;
	
	list_for_each_entry(tk, &ticket_list, list) {
		if (tk->handle == handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("BUG: ticket_write failed "
			  "(ticket handle %d does not exist)", handle);
		return -1;
	}

	tk->owner = result->owner;
	tk->expires = result->expires;

	if (tk->owner == ticket_get_myid()) {
		pcmk_handler.store_ticket(tk->id, tk->owner, tk->expires);
		pcmk_handler.grant_ticket(tk->id);
	} else if (tk->owner == -1) {
		pcmk_handler.store_ticket(tk->id, tk->owner, tk->expires);
		pcmk_handler.revoke_ticket(tk->id);
	} else
		pcmk_handler.store_ticket(tk->id, tk->owner, tk->expires);

	return 0; 
}

int ticket_recv(void *msg, int msglen)
{
	struct booth_msghdr *hdr;
	char *data;

	hdr = msg;
	if (ntohs(hdr->magic) != PAXOS_MAGIC ||
	    ntohl(hdr->len) != msglen) {
		log_error("message received error");
		return -1;
	}
	data = (char *)msg + sizeof(struct booth_msghdr);

	return paxos_lease_on_receive(data,
				      msglen - sizeof(struct booth_msghdr));
}

int grant_ticket(char *ticket, int force)
{
	struct ticket *tk;
	int found = 0;

	if (force) {
		pcmk_handler.store_ticket(ticket, ticket_get_myid(), -1);
		pcmk_handler.grant_ticket(ticket);
		return BOOTHC_RLT_SYNC_SUCC;
	}

	list_for_each_entry(tk, &ticket_list, list) {
		if (!strcmp(tk->id, ticket)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("ticket %s does not exist", ticket);
		return BOOTHC_RLT_SYNC_FAIL;
	}

	if (tk->owner == ticket_get_myid())
		return BOOTHC_RLT_SYNC_SUCC;
	else {
		paxos_lease_acquire(tk->handle, 1, end_acquire);
		return BOOTHC_RLT_ASYNC;
	}
}

int revoke_ticket(char *ticket, int force)
{
	struct ticket *tk;
	int found = 0;

	list_for_each_entry(tk, &ticket_list, list) {
		if (!strcmp(tk->id, ticket)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("ticket %s does not exist", ticket);
		return BOOTHC_RLT_SYNC_FAIL;
	}

	if (force) {
		pcmk_handler.store_ticket(tk->id, -1, 0);
		pcmk_handler.revoke_ticket(tk->id);
	}

	if (tk->owner == -1)
		return BOOTHC_RLT_SYNC_SUCC;
	else {
		paxos_lease_release(tk->handle);
		return BOOTHC_RLT_ASYNC;
	}	
}

int list_ticket(char **pdata, unsigned int *len)
{
	struct ticket *tk;
	char tmp[TK_LINE];

	*pdata = NULL;
	*len = 0;
	list_for_each_entry(tk, &ticket_list, list) {
		memset(tmp, 0, TK_LINE);
		snprintf(tmp, TK_LINE, "ticket: %s, owner: %d, expires: %llu\n",
			 tk->id, tk->owner, tk->expires);
		*pdata = realloc(*pdata, *len + TK_LINE);
		if (*pdata == NULL)
			return -ENOMEM;
		memset(*pdata + *len, 0, TK_LINE);
		memcpy(*pdata + *len, tmp, TK_LINE);
		*len += TK_LINE;
	}

	return 0;
}

const struct paxos_lease_operations ticket_operations = {
	.get_myid	= ticket_get_myid,
	.send		= ticket_send,
	.broadcast	= ticket_broadcast,
	.catchup	= ticket_read,
	.notify		= ticket_write,
};

int setup_ticket(void)
{
	struct ticket *tk, *tmp;
	int i, rv;
	pl_handle_t plh;
		
	role = malloc(booth_conf->node_count * sizeof(unsigned char));
	if (!role)
		return -ENOMEM;
	memset(role, 0, booth_conf->node_count * sizeof(unsigned char));
	for (i = 0; i < booth_conf->node_count; i++) {
		if (booth_conf->node[i].type == SITE)
			role[i] = PROPOSER | ACCEPTOR | LEARNER;
		else if (booth_conf->node[i].type == ARBITRATOR)
			role[i] = ACCEPTOR | LEARNER;
	}

	for (i = 0; i < booth_conf->ticket_count; i++) {
		tk = malloc(sizeof(struct ticket));
		if (!tk) {
			rv = -ENOMEM;
			goto out;
		}
		memset(tk, 0, sizeof(struct ticket));
		strcpy(tk->id, booth_conf->ticket[i].name);
		tk->owner = -1;
		tk->expiry = booth_conf->ticket[i].expiry;
		if (!tk->expiry)
			tk->expiry = DEFAULT_TICKET_EXPIRY;
		list_add_tail(&tk->list, &ticket_list); 

		plh = paxos_lease_init(tk->id,
				       BOOTH_NAME_LEN,
				       tk->expiry,
				       booth_conf->node_count,
				       1,
				       role,
				       ticket_priority(i),
				       &ticket_operations);
		if (plh <= 0) {
			log_error("paxos lease initialization failed");
			rv = plh;
			goto out;
		}
		tk->handle = plh;
	}

	return 0;

out:
	list_for_each_entry_safe(tk, tmp, &ticket_list, list) {
		list_del(&tk->list);
	}
	free(role);

	return rv;
}
