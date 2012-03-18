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
#include "paxos.h"
#include "paxos_lease.h"
#include "transport.h"
#include "config.h"
#include "timer.h"
#include "list.h"
#include "log.h"

#define PAXOS_LEASE_SPACE		"paxoslease"
#define PLEASE_VALUE_LEN		1024

struct paxos_lease_msghdr {
	int leased;
};

struct paxos_lease_value {
	char name[PAXOS_NAME_LEN+1];
	int owner;
	int expiry;
	int release;	
};

struct lease_state {
	int round;
	struct paxos_lease_value *plv;
	unsigned long long expires;
	struct timerlist *timer1;
	struct timerlist *timer2;
};

struct paxos_lease {
	char name[PAXOS_NAME_LEN+1];
	pi_handle_t pih;
	struct lease_state proposer;
	struct lease_state acceptor;
	int owner;
	int expiry;
	int renew;
	int failover;
	int release;
	unsigned long long expires;
	void (*end_lease) (pi_handle_t, int);
	struct timerlist *timer;
	struct list_head list;
};

static LIST_HEAD(lease_head);

static int myid = -1;
static struct paxos_operations *px_op = NULL;
const struct paxos_lease_operations *p_l_op;
ps_handle_t ps_handle = 0;

static void end_paxos_request(pi_handle_t handle, int round, int result)
{
	struct paxos_lease *pl;
	int found = 0;

	list_for_each_entry(pl, &lease_head, list) {
		if (pl->pih == handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("cound not found the handle for paxos lease: %ld",
			  handle);
		return;
	}

	if (round != pl->proposer.round) {
		log_error("current paxos round is not the proposer round, "
			  "current round: %d, proposer round: %d",
			  round, pl->proposer.round);
		return;
	}

	if (pl->end_lease)
		pl->end_lease((pl_handle_t)pl, result);
		
	return;	
}

static void renew_expires(unsigned long data)
{
	struct paxos_lease *pl = (struct paxos_lease *)data;
	struct paxos_lease_value value;

	log_debug("renew expires ...");

	memset(&value, 0, sizeof(struct paxos_lease_value));
	strncpy(value.name, pl->name, PAXOS_NAME_LEN + 1);
	value.owner = myid;
	value.expiry = pl->expiry;
	if (pl->release)
		value.release = 1;
	paxos_propose(pl->pih, &value, pl->proposer.round);
}

static void lease_expires(unsigned long data)
{
	struct paxos_lease *pl = (struct paxos_lease *)data;
	pl_handle_t plh = (pl_handle_t)pl;
	struct paxos_lease_result plr;

	log_debug("lease expires ...");
	pl->owner = -1;
	strcpy(plr.name, pl->name);
	plr.owner = -1;
	plr.expires = 0;
	plr.ballot = pl->acceptor.round;
	p_l_op->notify(plh, &plr);
		
	if (pl->proposer.timer1)
		del_timer(&pl->proposer.timer1);
	if (pl->proposer.timer2)
		del_timer(&pl->proposer.timer2);
	if (pl->acceptor.timer1)
		del_timer(&pl->acceptor.timer1);
	if (pl->acceptor.timer2)
		del_timer(&pl->acceptor.timer2);

	if (pl->failover)
		paxos_lease_acquire(plh, 1, NULL);
}

static void lease_retry(unsigned long data)
{
	struct paxos_lease *pl = (struct paxos_lease *)data;
	struct paxos_lease_value value;
	int round;

	log_debug("lease_retry ...");
	if (pl->proposer.timer2)
		del_timer(&pl->proposer.timer2);
	if (pl->owner == myid) {
		log_debug("already got the lease, no need to retry");
		return;
	}

	memset(&value, 0, sizeof(struct paxos_lease_value));
	strncpy(value.name, pl->name, PAXOS_NAME_LEN + 1);
	value.owner = myid;
	value.expiry = pl->expiry;

	round = paxos_round_request(pl->pih, &value, &pl->acceptor.round,
				     end_paxos_request);

	if (round > 0)
		pl->proposer.round = round;
}

int paxos_lease_acquire(pl_handle_t handle,
			int renew,
			void (*end_acquire) (pl_handle_t handle, int result))
{
	struct paxos_lease *pl = (struct paxos_lease *)handle;
	struct paxos_lease_value value;
	int round;

	memset(&value, 0, sizeof(struct paxos_lease_value));
	strncpy(value.name, pl->name, PAXOS_NAME_LEN + 1);
	value.owner = myid;
	value.expiry = pl->expiry;
	pl->renew = renew;
	pl->end_lease = end_acquire;
	pl->release = 0;

	round = paxos_round_request(pl->pih, &value, &pl->acceptor.round,
				     end_paxos_request);
	pl->proposer.timer2 = add_timer(1 * pl->expiry / 10, (unsigned long)pl,
					lease_retry);
	if (round <= 0)
		return -1;
	else {
		pl->proposer.round = round;	
		return 0;
	}
}

int paxos_lease_release(pl_handle_t handle)
{
	struct paxos_lease *pl = (struct paxos_lease *)handle;

	pl->release = 1;

	return 0;
}

static int lease_catchup(pi_handle_t handle)
{
	struct paxos_lease *pl;
	struct paxos_lease_result plr;
	int found = 0;

	list_for_each_entry(pl, &lease_head, list) {
		if (pl->pih == handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("could not find the lease handle: %ld", handle);
		return -1;
	}

	p_l_op->catchup(pl->name, &pl->owner, &pl->proposer.round, &pl->expires);
	log_debug("catchup result: name: %s, owner: %d, ballot: %d, expires: %llu",
		  (char *)pl->name, pl->owner, pl->proposer.round, pl->expires);

	if (pl->owner == -1)
		return 0;

	if (current_time() > pl->expires) {
		plr.owner = pl->owner = -1;
		plr.expires = pl->expires = 0;
		strcpy(plr.name, pl->name);
		p_l_op->notify((pl_handle_t)pl, &plr);
		return 0;
	}

	if (pl->owner == myid) {
		pl->acceptor.timer1 = add_timer(pl->expires - current_time(),
						(unsigned long)pl,
						lease_expires);
		if (current_time() < pl->expires - 1 * pl->expiry / 5)
			pl->proposer.timer1 = add_timer(pl->expires
							- 1 * pl->expiry / 5
							- current_time(),
							(unsigned long)pl,
							renew_expires);
	} else
		pl->acceptor.timer1 = add_timer(pl->expires - current_time(),
						(unsigned long)pl,
						lease_expires);

	plr.owner = pl->owner;
	plr.expires = pl->expires;
	plr.ballot = pl->proposer.round;
	strcpy(plr.name, pl->name);
	p_l_op->notify((pl_handle_t)pl, &plr);

	return 0;	
}

static int lease_prepared(pi_handle_t handle __attribute__((unused)),
			  void *header)
{
	struct paxos_lease_msghdr *hdr = header;

	if (hdr->leased) {
		log_debug("already leased");
		return 0;
	} else {
		log_debug("not leased");
		return 1;
	}
}

static int handle_lease_request(pi_handle_t handle, void *header)
{
	struct paxos_lease_msghdr *hdr;
	struct paxos_lease *pl;
	int found = 0;

	hdr = header;

	list_for_each_entry(pl, &lease_head, list) {
		if (pl->pih == handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("could not find the lease handle: %ld", handle);
		return -1;
	}

	if (pl->owner == -1) {
		log_debug("has not been leased");
		hdr->leased = 0;
	} else {
		log_debug("has been leased");
		hdr->leased = 1;
	}

	return 0;
}

static int lease_propose(pi_handle_t handle,
			 void *extra __attribute__((unused)),
			 int round, void *value)
{
	struct paxos_lease *pl;
	int found = 0;

	list_for_each_entry(pl, &lease_head, list) {
		if (pl->pih == handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("could not find the lease handle: %ld", handle);
		return -1;
	}

	if (round != pl->proposer.round) {
		log_error("current round is not the proposer round, "
			  "current round: %d, proposer round: %d",
			  round, pl->proposer.round);
		return -1;
	}

	if (!pl->proposer.plv) {
		pl->proposer.plv = malloc(sizeof(struct paxos_lease_value));
		if (!pl->proposer.plv) {
			log_error("could not alloc mem for propsoer plv");
			return -ENOMEM;
		}
	}
	memcpy(pl->proposer.plv, value, sizeof(struct paxos_lease_value));

	if (pl->proposer.timer1)
		del_timer(&pl->proposer.timer1);

	if (pl->renew) {
		pl->proposer.timer1 = add_timer(4 * pl->expiry / 5,
						(unsigned long)pl,
						renew_expires);
		pl->proposer.expires = current_time() + 4 * pl->expiry / 5;
	} else {
		pl->proposer.timer1 = add_timer(pl->expiry, (unsigned long)pl,
						lease_expires);
		pl->proposer.expires = current_time() + pl->expiry;
	}

	return 0;
}

static int lease_accepted(pi_handle_t handle,
			  void *extra __attribute__((unused)),
			  int round, void *value)
{
	struct paxos_lease *pl;
	int found = 0;

	list_for_each_entry(pl, &lease_head, list) {
		if (pl->pih == handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("could not find the lease handle: %ld", handle);
		return -1;
	}

	pl->acceptor.round = round;
	if (!pl->acceptor.plv) {
		pl->acceptor.plv = malloc(sizeof(struct paxos_lease_value));
		if (!pl->acceptor.plv) {
			log_error("could not alloc mem for acceptor plv");
			return -ENOMEM;
		}
	}
	memcpy(pl->acceptor.plv, value, sizeof(struct paxos_lease_value));

	if (pl->acceptor.timer1 && pl->acceptor.timer2 != pl->acceptor.timer1)
		del_timer(&pl->acceptor.timer1);
	pl->acceptor.timer1 = add_timer(pl->expiry, (unsigned long)pl,
					lease_expires);
	pl->acceptor.expires = current_time() + pl->expiry;

	return 0;	
}

static int lease_commit(pi_handle_t handle,
			void *extra __attribute__((unused)),
			int round)
{
	struct paxos_lease *pl;
	struct paxos_lease_result plr;
	int found = 0;

	list_for_each_entry(pl, &lease_head, list) {
		if (pl->pih == handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("could not find the lease handle: %ld", handle);
		return -1;
	}

	if (round != pl->proposer.round) {
		log_error("current round is not the proposer round, "
			  "current round: %d, proposer round: %d",
			  round, pl->proposer.round);
		return -1;
	}

	pl->owner = pl->proposer.plv->owner;
	pl->expiry = pl->proposer.plv->expiry;
	pl->release = pl->proposer.plv->release;
	if (pl->acceptor.timer2 != pl->acceptor.timer1) {
		if (pl->acceptor.timer2)
			del_timer(&pl->acceptor.timer2);
		pl->acceptor.timer2 = pl->acceptor.timer1;
	}

	strcpy(plr.name, pl->proposer.plv->name);
	plr.owner = pl->proposer.plv->owner;
	plr.expires = current_time() + pl->proposer.plv->expiry;
	plr.ballot = round;

	if (pl->release) {
		if (pl->acceptor.timer2)
			del_timer(&pl->acceptor.timer2);
		if (pl->acceptor.timer1)
			del_timer(&pl->acceptor.timer1);
		if (pl->proposer.timer2)
			del_timer(&pl->proposer.timer2);
		if (pl->proposer.timer1)
			del_timer(&pl->proposer.timer1);
		plr.owner = pl->owner = -1;
		plr.expires = 0;
	}

	p_l_op->notify((pl_handle_t)pl, &plr);

	return 0;	
}

static int lease_learned(pi_handle_t handle,
			 void *extra __attribute__((unused)),
			 int round)
{
	struct paxos_lease *pl;
	struct paxos_lease_result plr;
	int found = 0;

	list_for_each_entry(pl, &lease_head, list) {
		if (pl->pih == handle) {
			found = 1;
			break;
		}
	}
	if (!found) {
		log_error("could not find the lease handle: %ld", handle);
		return -1;
	}

	if (round != pl->acceptor.round) {
		log_error("current round is not the proposer round, "
			  "current round: %d, proposer round: %d",
			  round, pl->proposer.round);
		return -1;
	}

	pl->owner = pl->acceptor.plv->owner;
	pl->expiry = pl->acceptor.plv->expiry;
	pl->release = pl->acceptor.plv->release;
	if (pl->acceptor.timer2 != pl->acceptor.timer1) {
		if (pl->acceptor.timer2)
			del_timer(&pl->acceptor.timer2);
		pl->acceptor.timer2 = pl->acceptor.timer1;
	}

	strcpy(plr.name, pl->acceptor.plv->name);
	plr.owner = pl->acceptor.plv->owner;
	plr.expires = current_time() + pl->acceptor.plv->expiry;
	plr.ballot = round;

	if (pl->release) {
		if (pl->acceptor.timer2)
			del_timer(&pl->acceptor.timer2);
		if (pl->acceptor.timer1)
			del_timer(&pl->acceptor.timer1);
		plr.owner = pl->owner = -1;
		plr.expires = 0;
	}

	p_l_op->notify((pl_handle_t)pl, &plr);

	return 0;
}

pl_handle_t paxos_lease_init(const void *name,
			     unsigned int namelen,
			     int expiry,
			     int number,
			     int failover,
			     unsigned char *role,
			     int *prio,
			     const struct paxos_lease_operations *pl_op)
{
	ps_handle_t psh;
	pi_handle_t pih;
	struct paxos_lease *lease;

	if (namelen > PAXOS_NAME_LEN) {
		log_error("length of paxos name is too long (%u)", namelen);
		return -EINVAL;
	}

	if (myid == -1)
		myid = pl_op->get_myid();

	if (!ps_handle) {
		px_op = malloc(sizeof(struct paxos_operations));
		if (!px_op) {
			log_error("could not alloc for paxos operations");
			return -ENOMEM;
		}
		memset(px_op, 0, sizeof(struct paxos_operations));
		px_op->get_myid = pl_op->get_myid;
		px_op->send = pl_op->send;
		px_op->broadcast = pl_op->broadcast;
		px_op->catchup = lease_catchup;
		px_op->prepare = lease_prepared;
		px_op->promise = handle_lease_request;
		px_op->propose = lease_propose;
		px_op->accepted = lease_accepted;
		px_op->commit = lease_commit;
		px_op->learned = lease_learned;
		p_l_op = pl_op;

		psh = paxos_space_init(PAXOS_LEASE_SPACE,
				       number,
				       sizeof(struct paxos_lease_msghdr),
				       PLEASE_VALUE_LEN,
				       role,
				       px_op);
		if (psh <= 0) {
			log_error("failed to initialize paxos space: %ld", psh);
			free(px_op);
			px_op = NULL;	
			return psh;
		}
		ps_handle = psh; 
	}
	
	lease = malloc(sizeof(struct paxos_lease));
	if (!lease) {
		log_error("cound not alloc for paxos lease");
		return -ENOMEM;
	}
	memset(lease, 0, sizeof(struct paxos_lease));
	strncpy(lease->name, name, PAXOS_NAME_LEN + 1);
	lease->owner = -1;
	lease->expiry = expiry;
	lease->failover = failover;
	list_add_tail(&lease->list, &lease_head);

	pih = paxos_instance_init(ps_handle, name, prio);
	if (pih <= 0) {
		log_error("failed to initialize paxos instance: %ld", pih);
		free(lease);	
		return pih;
	}
	lease->pih = pih;

	return (pl_handle_t)lease;
}

int paxos_lease_status_recovery(pl_handle_t handle)
{
	struct paxos_lease *pl = (struct paxos_lease *)handle;

	if (paxos_recovery_status_get(pl->pih) == 1) {
		pl->renew = 1;
		if (paxos_catchup(pl->pih) == 0)
			paxos_recovery_status_set(pl->pih, 0);
	}

	return 0;	
}

int paxos_lease_on_receive(void *msg, int msglen)
{
	return paxos_recvmsg(msg, msglen);
}

int paxos_lease_exit(pl_handle_t handle)
{
	struct paxos_lease *pl = (struct paxos_lease *)handle;

	if (px_op)
		free(px_op);

	if (pl->proposer.plv)
		free(pl->proposer.plv);
	if (pl->proposer.timer1)
		del_timer(&pl->proposer.timer1);
	if (pl->proposer.timer2)
		del_timer(&pl->proposer.timer2);
	if (pl->acceptor.plv)
		free(pl->acceptor.plv);
	if (pl->acceptor.timer1)
		del_timer(&pl->acceptor.timer1);
	if (pl->acceptor.timer2)
		del_timer(&pl->acceptor.timer2);

	return 0;
}
