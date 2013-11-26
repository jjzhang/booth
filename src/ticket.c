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
#include "inline-fn.h"
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

#endif

#define foreach_ticket(i_,t_) for(i=0; (t_=booth_conf->ticket+i, i<booth_conf->ticket_count); i++)
#define foreach_node(i_,n_) for(i=0; (n_=booth_conf->node+i, i<booth_conf->node_count); i++)

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

#if 0
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
#endif


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


#if 0
void end_acquire(pl_handle_t handle, int error);
void end_acquire(pl_handle_t handle, int error)
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

void end_release(pl_handle_t handle, int error);
void end_release(pl_handle_t handle, int error)
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

int ticket_send(unsigned long id, void *value, int len);
int ticket_send(unsigned long id, void *value, int len)
{
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
	assert(0);
}

static int ticket_broadcast(void *value, int vlen)
{
	struct booth_msghdr *hdr;
	int tlen ;
	= sizeof(*hdr) + vlen;
	char buf[tlen];

	hdr = (void*)buf;
	hdr->magic = htons(PAXOS_MAGIC);
	hdr->len = htonl(tlen);
	memcpy(hdr->data, value, vlen);

	return transport()->broadcast(hdr, tlen);
}

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


static void ticket_parse(struct ticket_config *tk,
		struct boothc_ticket_msg *tmsg)
{
	struct ticket_paxos_state *tps;

	tps = &tk->current_state;

	if (tps->ballot < ntohl(tmsg->ticket.ballot))
		tps->ballot = ntohl(tmsg->ticket.ballot);
	if (CATCHED_VALID_TMSG == ntohl(tmsg->header.result)) {
		tps->expires = current_time() + ntohl(tmsg->ticket.expiry);

		if (!find_nodeid_in_config( ntohl(tmsg->ticket.owner),
					&tps->owner))
			log_error("wrong nodeid %x as ticket owner, msg from %x",
					tmsg->ticket.owner, tmsg->header.from);
	}
}


/** Find out what others think about this ticket.
 *
 * If we're a SITE, we can ask (and have to tell) Pacemaker.
 * An ARBITRATOR can only ask others. */
static int ticket_catchup(struct ticket_config *tk)
{
	struct ticket_paxos_state *tps;
	int i, rv = 0;
	uint32_t owner;
	struct booth_node *node;
	struct boothc_ticket_msg msg;
	time_t now;

	time(&now);
	tps = &tk->current_state;

	if (local->type != ARBITRATOR) {
		pcmk_handler.load_ticket(tk->name,
				&owner,
				&tps->ballot,
				&tps->expires);

		/* No check, node could have been deconfigured. */
		find_nodeid_in_config(owner, &tps->owner);
		if (now >= tps->expires) {
			tps->owner = NULL;
			tps->expires = 0;
		}
	}


	foreach_node(i, node) {
		if (node->type == SITE &&
				!(node->local)) {
			init_ticket_msg(&msg, CMD_CATCHUP);
			strncpy(msg.ticket.id, tk->name, sizeof(msg.ticket.id));

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

			/* TODO: check header? in tcp recv? */

			log_debug("got catchup result from %s", node->addr_string);
			ticket_parse(tk, &msg);
close:
			booth_transport[TCP].close(node);
		}
	}


	if (now >= tps->expires) {
		tps->owner = NULL;
		tps->expires = 0;
	}

	if (local->type != ARBITRATOR) {
		pcmk_handler.store_ticket(tk->name,
				tps->owner->nodeid,
				tps->ballot,
				tps->expires);
		if (tps->owner == local)
			pcmk_handler.grant_ticket(tk->name);
		else
			pcmk_handler.revoke_ticket(tk->name);
	}

	return rv;
}


int ticket_write(struct ticket_config *tk);
int ticket_write(struct ticket_config *tk)
{
	struct ticket_paxos_state *tps;

	tps = &tk->current_state;

	pcmk_handler.store_ticket(tk->name,
			tps->owner->nodeid, tps->ballot, tps->expires);

	if (tps->owner == local) {
		pcmk_handler.grant_ticket(tk->name);
	} else if (!tps->owner) {
		pcmk_handler.revoke_ticket(tk->name);
	}

	return 0;
}


void ticket_status_recovery(pl_handle_t handle);
void ticket_status_recovery(pl_handle_t handle)
{
	paxos_lease_status_recovery(handle);
}

#if 0
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
#endif

int grant_ticket(struct ticket_config *tk)
{
	struct ticket_paxos_state *tps;

	tps = &tk->current_state;
	if (tps->owner == local)
		return RLT_SYNC_SUCC;

	/* TODO */
#if 0
	int ret = paxos_lease_acquire(tk->handle, CLEAR_RELEASE,
			1, end_acquire);
	if (ret >= 0)
		tk->ballot = ret;
	return (ret < 0)? RLT_SYNC_FAIL: RLT_ASYNC;
#endif
	return 0;
}


int revoke_ticket(struct ticket_config *tk)
{
	struct ticket_paxos_state *tps;

	tps = &tk->current_state;
	if (!tps->owner)
		return RLT_SYNC_SUCC;

	/* TODO */
#if 0
	int ret = paxos_lease_release(tk->handle, end_release);
	if (ret >= 0)
		tk->ballot = ret;
	return (ret < 0)? RLT_SYNC_FAIL: RLT_ASYNC;
#endif
	return 0;
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
			strftime(timeout_str, sizeof(timeout_str), "%G",
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


int ticket_answer_catchup(struct ticket_msg *msg, struct ticket_config *tk)
{
	struct ticket_paxos_state *tps;

	tps = &tk->current_state;
	msg->ballot = htonl(tps->ballot);

	if (tps->owner == local && time(NULL) < tps->expires) {
		msg->expiry = htonl(tk->expires - current_time());
		msg->owner = htonl(tk->owner);
		return CATCHED_VALID_TMSG;
	}

	return -1;
}

#if 0

const struct paxos_lease_operations ticket_operations = {
	.send		= ticket_send,
	.broadcast	= ticket_broadcast,
	.catchup	= ticket_catchup,
	.notify		= ticket_write,
};
#endif

int setup_ticket(void)
{
	struct ticket_config *tk;
	int i;

	 /* TODO */
	foreach_ticket(i, tk) {
		ticket_catchup(tk);
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
		goto ex;

	init_header(&hdr, CMD_LIST, RLT_SUCCESS, sizeof(hdr) + olen);
	if (send_header_only(fd, &hdr) < 0)
		goto ex;

	if (olen)
		do_write(fd, data, olen);

ex:
	return;
}
