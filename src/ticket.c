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
	struct booth_site *node;

	if (!check_max_len_valid(site, sizeof(node->addr_string)))
		return 0;

	if (find_site_by_name(site, &node)) {
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
	struct booth_site *to = NULL;
	struct boothc_ticket_msg msg;

	foreach_node(i, to)
		if (booth_conf->node[i].site_id == id) {
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
	time_t now;


	tps = &tk->current_state;
	time(&now);

	if (tps->ballot < ntohl(tmsg->ticket.ballot))
		tps->ballot = ntohl(tmsg->ticket.ballot);

	if (CATCHED_VALID_TMSG == ntohl(tmsg->header.result)) {
		tps->expires = now + ntohl(tmsg->ticket.expiry);

		if (!find_site_by_id( ntohl(tmsg->ticket.owner),
					&tps->owner))
			log_error("wrong site_id %x as ticket owner, msg from %x",
					tmsg->ticket.owner, tmsg->header.from);
	}


	if (now >= tps->expires) {
		tps->owner = NULL;
		tps->expires = 0;
	}

	if (local->type != ARBITRATOR) {
		pcmk_handler.store_ticket(tk->name,
				get_node_id(tps->owner),
				tps->ballot,
				tps->expires);
		if (tps->owner == local)
			pcmk_handler.grant_ticket(tk->name);
		else
			pcmk_handler.revoke_ticket(tk->name);
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
	struct booth_site *site;
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
		find_site_by_id(owner, &tps->owner);
		if (now >= tps->expires) {
			tps->owner = NULL;
			tps->expires = 0;
		}
	}


	foreach_node(i, site) {
		if (!site->local) {
			init_ticket_msg(&msg, CMD_CATCHUP);
			strncpy(msg.ticket.id, tk->name, sizeof(msg.ticket.id));

			log_debug("attempting catchup from %s", site->addr_string);

			rv = booth_udp_send(site, &msg, sizeof(msg));
		}
	}


	return rv;
}


int ticket_write(struct ticket_config *tk);
int ticket_write(struct ticket_config *tk)
{
	struct ticket_paxos_state *tps;

	tps = &tk->current_state;

	pcmk_handler.store_ticket(tk->name,
			tps->owner->site_id, tps->ballot, tps->expires);

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
//	paxos_lease_status_recovery(handle);
}


int message_recv(struct boothc_ticket_msg *msg, int msglen)
{
	int cmd, rv;
	uint32_t from;
	struct booth_site *dest;


	if (check_boothc_header(&msg->header, sizeof(*msg)) < 0 ||
			msglen != sizeof(*msg)) {
		log_error("message receive error");
		return -1;
	}


	from = ntohl(msg->header.from);
	if (!find_site_by_id(from, &dest)) {
		log_error("unknown sender: %08x", from);
		return -1;
	}


	cmd = ntohl(msg->header.cmd);
	switch (cmd) {
	case CMD_CATCHUP:
		rv = ticket_answer_catchup(msg);
		if (rv < 0)
			return rv;
		return booth_udp_send(dest, msg, sizeof(*msg));

	case CMR_CATCHUP:
		return ticket_process_catchup(msg);

	default:
		log_error("unprocessed message, cmd %x", cmd);
	}
	return 0;
}


int do_grant_ticket(struct ticket_config *tk)
{
	struct ticket_paxos_state *tps;

	tps = &tk->current_state;
	if (tps->owner == local)
		return RLT_SUCCESS;

	/* TODO */
#if 0
	int ret = paxos_lease_acquire(tk->handle, CLEAR_RELEASE,
			1, end_acquire);
	if (ret >= 0)
		tk->ballot = ret;
	return (ret < 0)? RLT_SYNC_FAIL: RLT_ASYNC;
#endif
	return RLT_SUCCESS;
}


int do_revoke_ticket(struct ticket_config *tk)
{
	struct ticket_paxos_state *tps;

	tps = &tk->current_state;
	if (!tps->owner)
		return RLT_SUCCESS;

	/* TODO */
#if 0
	int ret = paxos_lease_release(tk->handle, end_release);
	if (ret >= 0)
		tk->ballot = ret;
	return (ret < 0)? RLT_SYNC_FAIL: RLT_ASYNC;
#endif
	return RLT_SUCCESS;
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
			strftime(timeout_str, sizeof(timeout_str), "%F %T",
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
		return rv;

	init_header(&hdr, CMR_LIST, RLT_SUCCESS, sizeof(hdr) + olen);

	return send_header_plus(fd, &hdr, data, olen);
}


int ticket_answer_grant(int fd, struct boothc_ticket_msg *msg)
{
	int rv;
	struct ticket_config *tk;


	if (!check_ticket(msg->ticket.id, &tk)) {
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	if (tk->current_state.owner) {
		log_error("client want to get an granted "
				"ticket %s", msg->ticket.id);
		rv = RLT_OVERGRANT;
		goto reply;
	}

	rv = do_grant_ticket(tk);

reply:
	init_header(&msg->header, CMR_GRANT, rv, sizeof(*msg));
	return send_ticket_msg(fd, msg);
}


int ticket_answer_revoke(int fd, struct boothc_ticket_msg *msg)
{
	int rv;
	struct ticket_config *tk;

	if (!check_ticket(msg->ticket.id, &tk)) {
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	if (!tk->current_state.owner) {
		log_info("client want to revoke a free ticket \"%s\"",
				msg->ticket.id);
		rv = RLT_SUCCESS;
		goto reply;
	}

	rv = do_revoke_ticket(tk);

reply:
	init_header(&msg->header, CMR_REVOKE, rv, sizeof(*msg));
	return send_ticket_msg(fd, msg);
}


int ticket_answer_catchup(struct boothc_ticket_msg *msg)
{
	struct ticket_paxos_state *tps;
	struct ticket_config *tk;
	int rv, mine;


	if (!check_ticket(msg->ticket.id, &tk)) {
		rv = RLT_INVALID_ARG;
		goto reply;
	}

	log_debug("got catchup request for \"%s\" from %08x",
			msg->ticket.id, ntohl(msg->header.from));


	tps = &tk->current_state;

	mine = owner_and_valid(tk);

	/* We do _always_ answer.
	 * In case all booth daemons are restarted at the same time, nobody
	 * would answer any questions, leading to timeouts and delays.
	 * Just admit we don't know. */

	msg->ticket.expiry = htonl( mine );
	msg->ticket.owner  = htonl( get_node_id(tps->owner) );
	msg->ticket.ballot = htonl(tps->ballot);
	rv = RLT_SUCCESS;

reply:
	init_header(&msg->header, CMR_CATCHUP, rv, sizeof(*msg));
	return 1;
}


int ticket_process_catchup(struct boothc_ticket_msg *msg)
{
	struct ticket_config *tk;
	int rv;


	if (!check_ticket(msg->ticket.id, &tk)) {
		rv = RLT_INVALID_ARG;
		goto ex;
	}

	log_debug("got catchup answer for \"%s\" from %08x",
			msg->ticket.id, ntohl(msg->header.from));

	ticket_parse(tk, msg);
	rv = 0;

ex:
	log_debug("got catchup result from %x: result %d", ntohl(msg->header.from), rv);
	return rv;
}

