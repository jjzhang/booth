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
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "ticket.h"
#include "config.h"
#include "pacemaker.h"
#include "list.h"
#include "log.h"
#include "booth.h"
#include "timer.h"
#include "paxos_lease.h"
#include "paxos.h"

#define PAXOS_MAGIC		0xDB12
#define TK_LINE			256

#define CATCHED_VALID_TMSG	1

#if 0
struct booth_msghdr {
        uint16_t magic;
        uint16_t checksum;
        uint32_t len;
	char data[0];
} __attribute__((packed));

struct ticket {
	char id[BOOTH_NAME_LEN+1];
	pl_handle_t handle;
	int owner;
	int expiry;
	int ballot;
	unsigned long long expires;
	struct list_head list;
};

static LIST_HEAD(ticket_list);

/* Put into node data */
static unsigned char *role;
#endif

#define foreach_ticket(i_,t_) for(i=0; (t_=booth_conf->ticket+i, i<booth_conf->ticket_count); i++)
#define foreach_node(i_,n_) for(i=0; (n_=booth_conf->node+i, i<booth_conf->node_count); i++)

/* Untrusted input, must fit (incl. \0) in a buffer of max chars. */
int check_max_len_valid(char *s, int max)
{
	int i;
	for(i=0; i<BOOTH_NAME_LEN; i++)
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

int find_ticket_by_handle(pl_handle_t handle, struct ticket_config **found)
{
	int i;

	if (found)
		*found = NULL;

	for (i = 0; i < booth_conf->ticket_count; i++) {
		if (booth_conf->ticket[i].handle == handle) {
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
	struct booth_node *node;

	if (!check_max_len_valid(site, sizeof(node->addr_string)))
		return 0;

	if (find_site_in_config(site, &node)) {
		*is_local = node->local;
		return 1;
	}

	return 0;
}

static int * ticket_priority(int i)
{
	int j;

	/* TODO: need more precise check */
	/* WHAT???? node_count ticket?*/
	for (j = 0; j < booth_conf->node_count; j++) {
		if (booth_conf->ticket[i].weight[j] == 0)
			return NULL;
	}
	return booth_conf->ticket[i].weight;
}

static int ticket_get_myid(void)
{
	return transport()->get_myid();
}

static void end_acquire(pl_handle_t handle, int error)
{
	struct ticket_config *tk;

	log_debug("enter end_acquire");
	if (!find_ticket_by_handle(handle, &tk)) {
		log_error("BUG: ticket handle %ld does not exist", handle);
		return;
	}

	if (error)
		log_info("ticket %s failed granting for site %s, error:%s",
				tk->name, local->addr_string, strerror(error));
	else
		log_info("ticket %s was granted successfully for site %s",
				tk->name, local->addr_string);
	log_debug("exit end_acquire");
}

static void end_release(pl_handle_t handle, int error)
{
	struct ticket_config *tk;

	log_debug("enter end_release");
	if (!find_ticket_by_handle(handle, &tk)) {
		log_error("BUG: ticket handle %ld does not exist", handle);
		return;
	}

	if (error)
		log_info("ticket %s failed revoking on site %s, error:%s",
				tk->name, local->addr_string, strerror(error));
	else
		log_info("ticket %s was revoked successfully on site %s",
				tk->name, local->addr_string);

	log_debug("exit end_release");
}

static int ticket_send(unsigned long id, void *value, int len)
{
#if 0
	int i, rv = -1;
	struct booth_node *to = NULL;
	struct boothc_ticket_msg msg;

	foreach_node(i, to)
		if (booth_conf->node[i].nodeid == id) {
			to = booth_conf->node+i;
			break;
		}
	if (!to)
		return rv;

	memset(&msg, 0, sizeof(msg));
	hdr->magic = htons(PAXOS_MAGIC);
	hdr->len = htonl(sizeof(struct booth_msghdr) + len);
	memcpy((char *)buf + sizeof(struct booth_msghdr), value, len);

	rv = transport()->send(to, buf, sizeof(struct booth_msghdr) + len);

	frdee(buf);
	*/
	return rv;
#endif
	assert(0);
}

static int ticket_broadcast(void *value, int vlen)
{
	struct booth_msghdr *hdr;
	int tlen ;
#if 0
	= sizeof(*hdr) + vlen;
	char buf[tlen];

	hdr = (void*)buf;
	hdr->magic = htons(PAXOS_MAGIC);
	hdr->len = htonl(tlen);
	memcpy(hdr->data, value, vlen);

#endif
	return transport()->broadcast(hdr, tlen);
}
#if 0
static int ticket_read(const void *name, int *owner, int *ballot, 
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

	pcmk_handler.load_ticket(tk->id, &tk->owner, &tk->ballot, &tk->expires);
	*owner = tk->owner;
	*expires = tk->expires;
	*ballot = tk->ballot;
 
	return 0;
}
#endif
static int ticket_parse(struct boothc_ticket_msg *tmsg)
{
	struct ticket_config *tk;

	if (!find_ticket_by_name(tmsg->ticket.id, &tk))
		return -1;

	if (tk->ballot < ntohl(tmsg->ticket.ballot))
		tk->ballot = ntohl(tmsg->ticket.ballot);
	if (CATCHED_VALID_TMSG == ntohl(tmsg->header.result)) {
		tk->owner = ntohl(tmsg->ticket.owner);
		tk->expires = current_time() + ntohl(tmsg->header.expiry);
	}
}

static int ticket_catchup(const void *name, int *owner, int *ballot,
			  unsigned long long *expires)
{
	struct ticket_config *tk;
	int i, rv = 0;
	struct booth_node *node;
	struct boothc_ticket_msg msg;
	time_t now;

	time(&now);
	if (local->type != ARBITRATOR &&
			find_ticket_by_name(name, &tk)) {
		pcmk_handler.load_ticket(tk->name,
				&tk->owner,
				&tk->ballot,
				&tk->expires);
		if (now >= tk->expires) {
			tk->owner = NO_OWNER;
			tk->expires = 0;
		}
	}

	foreach_node(i, node) {
		if (node->type == SITE &&
				!(node->local)) {
			init_ticket_msg(&msg, BOOTHC_CMD_CATCHUP);
			strncpy(msg.ticket.id, name, BOOTH_NAME_LEN + 1);

			log_debug("attempting catchup from %s", node->addr_string);

			rv = booth_transport[TCP].open(node);
			if (rv < 0)
				continue;
			log_debug("connected to %s", node->addr_string);

			rv = booth_transport[TCP].send(node, &msg, sizeof(msg));
			if (rv != sizeof(msg))
				goto close;

			log_debug("sent catchup command to %s", node->addr_string);

			rv = booth_transport[TCP].recv(node, &msg, sizeof(&msg));
			if (rv != sizeof(msg))
				goto close;

			log_debug("got catchup result from %s", node->addr_string);
			ticket_parse(&msg);
close:
			booth_transport[TCP].close(node);
		}
	}


	if (find_ticket_by_name(name, &tk)) {
		if (local->type != ARBITRATOR) {
			if (current_time() >= tk->expires) {
				tk->owner = NO_OWNER;
				tk->expires = 0;
			}
			pcmk_handler.store_ticket(tk->name,
					tk->owner,
					tk->ballot,
					tk->expires);
			if (tk->owner == ticket_get_myid())
				pcmk_handler.grant_ticket(tk->name);
			else
				pcmk_handler.revoke_ticket(tk->name);
		}
		*owner = tk->owner;
		*expires = tk->expires;
		*ballot = tk->ballot;
	}

	return rv;
}

static int ticket_write(pl_handle_t handle, struct paxos_lease_result *result)
{
	struct ticket_config *tk;

	if (!find_ticket_by_handle(handle, &tk)) {
		log_error("BUG: ticket_write failed "
			  "(ticket handle %ld does not exist)", handle);
		return -1;
	}

	/* TODO: ntohl? */
	tk->owner = result->owner;
	tk->expires = result->expires;
	tk->ballot = result->ballot;

	pcmk_handler.store_ticket(tk->name, tk->owner, tk->ballot, tk->expires);
	if (tk->owner == ticket_get_myid()) {
		pcmk_handler.grant_ticket(tk->name);
	} else if (tk->owner == NO_OWNER) {
		pcmk_handler.revoke_ticket(tk->name);
	}

	return 0;
}

static void ticket_status_recovery(pl_handle_t handle)
{
	paxos_lease_status_recovery(handle);
}

int ticket_recv(struct boothc_ticket_msg *msg, int msglen)
{
	struct booth_msghdr *hdr;
	char *data;

	if (check_boothc_header(hdr, sizeof(*msg)) < 0 ||
			msglen != sizeof(*msg)) {
		log_error("message receive error");
		return -1;
	}
	return paxos_recvmsg(msg);
}

int grant_ticket(char *ticket)
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

	if (tk->owner == ticket_get_myid())
		return BOOTHC_RLT_SYNC_SUCC;
	else {
		int ret = paxos_lease_acquire(tk->handle, CLEAR_RELEASE,
				1, end_acquire);
		if (ret >= 0)
			tk->ballot = ret;
		return (ret < 0)? BOOTHC_RLT_SYNC_FAIL: BOOTHC_RLT_ASYNC;
	}
}

int revoke_ticket(char *ticket)
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

	if (tk->owner == NO_OWNER)
		return BOOTHC_RLT_SYNC_SUCC;
	else {
		int ret = paxos_lease_release(tk->handle, end_release);
		if (ret >= 0)
			tk->ballot = ret;
		return (ret < 0)? BOOTHC_RLT_SYNC_FAIL: BOOTHC_RLT_ASYNC;
	}	
}

int get_ticket_info(char *name, int *owner, int *expires)
{
	struct ticket *tk;

	list_for_each_entry(tk, &ticket_list, list) {
		if (!strncmp(tk->id, name, BOOTH_NAME_LEN + 1)) {
			if(owner)
				*owner = tk->owner;
			if(expires)
				*expires = tk->expires;
			return 0;
		}
	}

	return -1;
}

int list_ticket(char **pdata, unsigned int *len)
{
	struct ticket *tk;
	char timeout_str[100];
	char node_name[BOOTH_NAME_LEN];
	char tmp[TK_LINE];

	*pdata = NULL;
	*len = 0;
	list_for_each_entry(tk, &ticket_list, list) {
		memset(tmp, 0, TK_LINE);
		strncpy(timeout_str, "INF", sizeof(timeout_str));
		strncpy(node_name, "None", sizeof(node_name));

		if (tk->owner < MAX_NODES && tk->owner > NO_OWNER)
			strncpy(node_name, booth_conf->node[tk->owner].addr_string,
					sizeof(node_name));
		if (tk->expires != 0)
			strftime(timeout_str, sizeof(timeout_str), "%Y/%m/%d %H:%M:%S",
					localtime((time_t *)&tk->expires));
		snprintf(tmp, TK_LINE, "ticket: %s, owner: %s, expires: %s\n",
			 tk->id, node_name, timeout_str);
		*pdata = realloc(*pdata, *len + TK_LINE);
		if (*pdata == NULL)
			return -ENOMEM;
		memset(*pdata + *len, 0, TK_LINE);
		memcpy(*pdata + *len, tmp, TK_LINE);
		*len += TK_LINE;
	}

	return 0;
}

int catchup_ticket(struct ticket_msg *msg, struct ticket_config *tc)
{
	msg->ballot = htonl(tk->ballot);
	if (tk->owner == ticket_get_myid()
			&& current_time() < tk->expires) {
		msg->expiry = htonl(tk->expires - current_time());
		msg->owner = htonl(tk->owner);
		return CATCHED_VALID_TMSG;
	}

	return -1;
}

const struct paxos_lease_operations ticket_operations = {
	.get_myid	= ticket_get_myid,
	.send		= ticket_send,
	.broadcast	= ticket_broadcast,
	.catchup	= ticket_catchup,
	.notify		= ticket_write,
};

int setup_ticket(void)
{
	struct ticket *tk, *tmp;
	int i, rv;
	pl_handle_t plh;
	int myid;
		
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
		tk->owner = NO_OWNER;
		tk->expiry = booth_conf->ticket[i].expiry;
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

	myid = ticket_get_myid();
	assert(myid < booth_conf->node_count);
	if (role[myid] & ACCEPTOR) {
		list_for_each_entry(tk, &ticket_list, list) {
			ticket_status_recovery(tk->handle);
		}
	}

	return 0;

out:
	list_for_each_entry_safe(tk, tmp, &ticket_list, list) {
		list_del(&tk->list);
	}
	free(role);

	return rv;
}
