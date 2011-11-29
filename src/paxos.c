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
#include "list.h"
#include "paxos.h"

typedef enum {
	INIT = 1,
	PREPARING,
	PROMISING,
	PROPOSING,
	ACCEPTING,
	RECOVERY,
} paxos_state_t;

struct proposal {
	int ballot_number;
	char value[0];
};

struct learned {
	int ballot;
	int number;
};

struct paxos_msghdr {
	paxos_state_t state;
	int from;
	char psname[PAXOS_NAME_LEN+1];
	char piname[PAXOS_NAME_LEN+1];
	int ballot_number;
	int reject;
	int proposer_id;
	unsigned int extralen;
	unsigned int valuelen;
};

struct proposer {
	int state;
	int open_number;
	int accepted_number;
	int proposed;
	struct proposal *proposal;
};

struct acceptor {
	int state;
	int highest_promised;
	struct proposal *accepted_proposal;
};

struct learner {
	int state;
	int learned_max;
	int learned_ballot;
	struct learned learned[0];
};

struct paxos_space;
struct paxos_instance;

struct proposer_operations {
	void (*prepare) (struct paxos_instance *,
			 int *);
	void (*propose) (struct paxos_space *,
			 struct paxos_instance *,
			 void *, int);
	void (*commit) (struct paxos_space *,
			struct paxos_instance *,
			void *, int);
};

struct acceptor_operations {
	void (*promise) (struct paxos_space *,
			 struct paxos_instance *,
			 void *, int);
	void (*accepted) (struct paxos_space *,
			  struct paxos_instance *,
			  void *, int);
};

struct learner_operations {
	void (*response) (struct paxos_space *,
			  struct paxos_instance *,
			  void *, int);
};
	

struct paxos_space {
	char name[PAXOS_NAME_LEN+1];
	unsigned int number;
	unsigned int extralen;
	unsigned int valuelen;
	const unsigned char *role;
	const struct paxos_operations *p_op;
	const struct proposer_operations *r_op;
	const struct acceptor_operations *a_op;
	const struct learner_operations *l_op;
	struct list_head list;
	struct list_head pi_head;
};

struct paxos_instance {
	char name[PAXOS_NAME_LEN+1];
	int round;
	int *prio;
	struct proposer *proposer;
	struct acceptor *acceptor;
	struct learner *learner;
	void (*end) (pi_handle_t pih, int round, int result);
	struct list_head list;
	struct paxos_space *ps;
};

static LIST_HEAD(ps_head);

static int have_quorum(struct paxos_space *ps, int member)
{
	int i, sum = 0;

	for (i = 0; i < ps->number; i++) {
		if (ps->role[i] & ACCEPTOR)
			sum++;
	}

	if (member * 2 > sum)
		return 1;
	else
		return 0;
}

static int next_ballot_number(struct paxos_instance *pi)
{
	int ballot;
	int myid = pi->ps->p_op->get_myid();

	if (pi->prio)
		ballot = pi->prio[myid];
	else
		ballot = myid;

	while (ballot <= pi->round)
		ballot += pi->ps->number;

	return ballot;
}

static void proposer_prepare(struct paxos_instance *pi, int *round)
{
	struct paxos_msghdr *hdr;
	void *msg;
	int msglen = sizeof(struct paxos_msghdr) + pi->ps->extralen;
	int ballot;

	msg = malloc(msglen);
	if (!msg) {
		*round = 0;
		return;
	}
	memset(msg, 0, msglen);
	hdr = msg;

	ballot = next_ballot_number(pi);

	hdr->state = htonl(PREPARING);
	hdr->from = htonl(pi->ps->p_op->get_myid());
	hdr->proposer_id = hdr->from;
	strcpy(hdr->psname, pi->ps->name);
	strcpy(hdr->piname, pi->name);
	hdr->ballot_number = htonl(ballot);
	hdr->extralen = htonl(pi->ps->extralen);

	if (pi->ps->p_op->broadcast)
		pi->ps->p_op->broadcast(msg, msglen);
	else {
		int i;
		for (i = 0; i < pi->ps->number; i++) {
			if (pi->ps->role[i] & ACCEPTOR)
				pi->ps->p_op->send(i, msg, msglen);
		}
	}

	free(msg);
	*round = ballot;
}

static void proposer_propose(struct paxos_space *ps,
			     struct paxos_instance *pi,
			     void *msg, int msglen)
{
	struct paxos_msghdr *hdr;
	pi_handle_t pih = (pi_handle_t)pi;
	void *extra, *value, *message;
	int ballot;

	if (msglen != sizeof(struct paxos_msghdr) + ps->extralen)
		return;
	hdr = msg;
	ballot = ntohl(hdr->ballot_number);

	if (ntohl(hdr->reject)) {
		pi->round = ballot;
		pi->end(pih, pi->round, -EAGAIN);
		return;
	}

	extra = (char *)msg + sizeof(struct paxos_msghdr);
	if (ps->p_op->prepare) {
		if (ps->p_op->prepare(pih, extra))
			pi->proposer->open_number++;
	} else
		pi->proposer->open_number++;

	if (!have_quorum(ps, pi->proposer->open_number))
		return;

	if (pi->proposer->proposed)
		return;
	pi->proposer->proposed = 1;

	value = pi->proposer->proposal->value;
	if (ps->p_op->propose)
		ps->p_op->propose(pih, extra, ballot, value);

	hdr->valuelen = htonl(ps->valuelen); 
	message = malloc(msglen + ps->valuelen);
	if (!message)
		return;
	memset(message, 0, msglen + ps->valuelen);
	memcpy(message, msg, msglen);
	memcpy((char *)message + msglen, value, ps->valuelen);
	pi->acceptor->state = PROPOSING;
	hdr = message;
	hdr->from = htonl(ps->p_op->get_myid());
	hdr->state = htonl(PROPOSING);

	if (ps->p_op->broadcast)
		ps->p_op->broadcast(message, msglen + ps->valuelen);
	else {
		int i;
		for (i = 0; i < ps->number; i++) {
			if (ps->role[i] & ACCEPTOR)
				ps->p_op->send(i, message,
					       msglen + ps->valuelen);
		}
	}
}

static void proposer_commit(struct paxos_space *ps,
			    struct paxos_instance *pi,
			    void *msg, int msglen)
{
	struct paxos_msghdr *hdr;
	pi_handle_t pih = (pi_handle_t)pi;
	void *extra;

	if (msglen != sizeof(struct paxos_msghdr) + ps->extralen)
		return;
	
	extra = (char *)msg + sizeof(struct paxos_msghdr);
	hdr = msg;

	pi->proposer->accepted_number++;

	if (!have_quorum(ps, pi->proposer->accepted_number))
		return;

	pi->round = ntohl(hdr->ballot_number);
	if (ps->p_op->commit)
		ps->p_op->commit(pih, extra, pi->round);
	pi->end(pih, pi->round, 0);	
}

static void acceptor_promise(struct paxos_space *ps,
			     struct paxos_instance *pi,
			     void *msg, int msglen)
{
	struct paxos_msghdr *hdr;
	unsigned long to;
	pi_handle_t pih = (pi_handle_t)pi;
	void *extra;

	if (pi->acceptor->state == RECOVERY)
		return;

	if (msglen != sizeof(struct paxos_msghdr) + ps->extralen)
		return;
	hdr = msg;
	extra = (char *)msg + sizeof(struct paxos_msghdr);

	if (ntohl(hdr->ballot_number) < pi->acceptor->highest_promised) {
		to = ntohl(hdr->from);
		hdr->from = htonl(ps->p_op->get_myid());
		hdr->state = htonl(PROMISING);
		hdr->reject = htonl(1);
		memset(extra, 0, ps->extralen);
		ps->p_op->send(to, msg, msglen);
		return;
	}
	pi->acceptor->highest_promised = ntohl(hdr->ballot_number);

	if (ps->p_op->promise)
		ps->p_op->promise(pih, extra);

	pi->acceptor->state = PROMISING;
	to = ntohl(hdr->from);
	hdr->from = htonl(ps->p_op->get_myid());
	hdr->state = htonl(PROMISING);
	ps->p_op->send(to, msg, msglen);	
}

static void acceptor_accepted(struct paxos_space *ps,
			      struct paxos_instance *pi,
			      void *msg, int msglen)
{
	struct paxos_msghdr *hdr;
	unsigned long to;
	pi_handle_t pih = (pi_handle_t)pi;
	void *extra, *value;
	int myid = ps->p_op->get_myid();
	int ballot;

	if (pi->acceptor->state == RECOVERY)
		return;

	if (msglen != sizeof(struct paxos_msghdr) + ps->extralen + ps->valuelen)
		return;
	hdr = msg;
	extra = (char *)msg + sizeof(struct paxos_msghdr);
	ballot = ntohl(hdr->ballot_number);

	if (ballot < pi->acceptor->highest_promised) {
		to = ntohl(hdr->from);
		hdr->from = htonl(myid);
		hdr->state = htonl(ACCEPTING);
		hdr->reject = htonl(1);
		ps->p_op->send(to, hdr, sizeof(struct paxos_msghdr));
		return;
	}

	value = pi->acceptor->accepted_proposal->value;
	memcpy(value, (char *)msg + sizeof(struct paxos_msghdr) + ps->extralen,
	       ps->valuelen);

	if (ps->p_op->accepted)
		ps->p_op->accepted(pih, extra, ballot, value);

	pi->acceptor->state = ACCEPTING;
	to = ntohl(hdr->from);
	hdr->from = htonl(myid);
	hdr->state = htonl(ACCEPTING);

	if (ps->p_op->broadcast)
		ps->p_op->broadcast(msg, sizeof(struct paxos_msghdr)
						+ ps->extralen);
	else {
		int i;
		for (i = 0; i < ps->number; i++) {
			if (ps->role[i] & LEARNER)
				ps->p_op->send(i, msg,
					       sizeof(struct paxos_msghdr)
					       + ps->extralen);
		}
		if (!(ps->role[to] & LEARNER))
			ps->p_op->send(to, msg, sizeof(struct paxos_msghdr)
						+ ps->extralen);	
	}
}

static void learner_response(struct paxos_space *ps,
			     struct paxos_instance *pi,
			     void *msg, int msglen)
{
	struct paxos_msghdr *hdr;
	pi_handle_t pih = (pi_handle_t)pi;
	void *extra;
	int i, unused, found = 0;
	int ballot;

	if (msglen != sizeof(struct paxos_msghdr) + ps->extralen)
		return;
	hdr = msg;	
	extra = (char *)msg + sizeof(struct paxos_msghdr);
	ballot = ntohl(hdr->ballot_number);

	for (i = 0; i < ps->number; i++) {
		if (!pi->learner->learned[i].ballot) {
			unused = i;
			break;
		}
		if (pi->learner->learned[i].ballot == ballot) {
			pi->learner->learned[i].number++;
			if (pi->learner->learned[i].number
			    > pi->learner->learned_max)
				pi->learner->learned_max
					= pi->learner->learned[i].number;
			found = 1;
			break;
		}
	}
	if (!found) {
		pi->learner->learned[unused].ballot = ntohl(hdr->ballot_number);
		pi->learner->learned[unused].number = 1;
	}

	if (!have_quorum(ps, pi->learner->learned_max))
		return;

	if (ps->p_op->learned)
		ps->p_op->learned(pih, extra, ballot);
}

const struct proposer_operations generic_proposer_operations = {
	.prepare		= proposer_prepare,
	.propose		= proposer_propose,
	.commit			= proposer_commit,
};

const struct acceptor_operations generic_acceptor_operations = {
	.promise		= acceptor_promise,
	.accepted		= acceptor_accepted,
};

const struct learner_operations generic_learner_operations = {
	.response		= learner_response,
}; 

ps_handle_t paxos_space_init(const void *name,
			     unsigned int number,
			     unsigned int extralen,
			     unsigned int valuelen,
			     const unsigned char *role,
			     const struct paxos_operations *p_op)
{
	struct paxos_space *ps;

	list_for_each_entry(ps, &ps_head, list) {
		if (!strcmp(ps->name, name))
			return -EEXIST;
	}
	
	if (!number || !valuelen || !p_op || !p_op->get_myid || !p_op->send)
		return -EINVAL;

	ps = malloc(sizeof(struct paxos_space));
	if (!ps)
		return -ENOMEM;
	memset(ps, 0, sizeof(struct paxos_space));

	strncpy(ps->name, name, PAXOS_NAME_LEN + 1);
	ps->number = number;
	ps->extralen = extralen;
	ps->valuelen = valuelen;
	ps->role = role;
	ps->p_op = p_op;
	ps->r_op = &generic_proposer_operations;
	ps->a_op = &generic_acceptor_operations;
	ps->l_op = &generic_learner_operations;

	list_add_tail(&ps->list, &ps_head);
	INIT_LIST_HEAD(&ps->pi_head);

	return (ps_handle_t)ps;
}

pi_handle_t paxos_instance_init(ps_handle_t handle, const void *name, int *prio)
{
	struct paxos_space *ps = (struct paxos_space *)handle;
	struct paxos_instance *pi;
	struct proposer *proposer;
	struct acceptor *acceptor;
	struct learner *learner;
	int myid, valuelen, rv;

	list_for_each_entry(pi, &ps->pi_head, list) {
		if (!strcmp(pi->name, name))
			return (pi_handle_t)pi;
	}

	if (handle <= 0 || !ps->p_op || !ps->p_op->get_myid) {
		rv = -EINVAL;
		goto out;
	}
	myid = ps->p_op->get_myid();
	valuelen = ps->valuelen; 

	pi = malloc(sizeof(struct paxos_instance));
	if (!pi) {
		rv = -ENOMEM;
		goto out;
	}
	memset(pi, 0, sizeof(struct paxos_instance));
	strncpy(pi->name, name, PAXOS_NAME_LEN + 1);

	if (prio) {
		pi->prio = malloc(ps->number * sizeof(int));
		if (!pi->prio) {
			rv = -ENOMEM;
			goto out_pi;
		}
		memcpy(pi->prio, prio, ps->number * sizeof(int));
	}

	if (ps->role[myid] & PROPOSER) {
		proposer = malloc(sizeof(struct proposer));
		if (!proposer) {
			rv = -ENOMEM;
			goto out_prio;
		}
		memset(proposer, 0, sizeof(struct proposer));
		proposer->state = INIT;

		proposer->proposal = malloc(sizeof(struct proposal) + valuelen);
		if (!proposer->proposal) {
			rv = -ENOMEM;
			goto out_proposer;
		}
		memset(proposer->proposal, 0,
		       sizeof(struct proposal) + valuelen);
		pi->proposer = proposer;
	}

	if (ps->role[myid] & ACCEPTOR) {
		acceptor = malloc(sizeof(struct acceptor));
		if (!acceptor) {
			rv = -ENOMEM;
			goto out_proposal;
		}
		memset(acceptor, 0, sizeof(struct acceptor));
		acceptor->state = INIT;

		acceptor->accepted_proposal = malloc(sizeof(struct proposal)
						     + valuelen);
		if (!acceptor->accepted_proposal) {
			rv = -ENOMEM;
			goto out_acceptor;
		}
		memset(acceptor->accepted_proposal, 0,
		       sizeof(struct proposal) + valuelen);
		pi->acceptor = acceptor;
	
		if (ps->p_op->catchup) {
			pi->acceptor->state = RECOVERY;
			ps->p_op->catchup(name);
			pi->acceptor->state = INIT;
		}
	}

	if (ps->role[myid] & LEARNER) {
		learner = malloc(sizeof(struct learner)
				 + ps->number * sizeof(struct learned));
		if (!learner) {
			rv = -ENOMEM;
			goto out_accepted_proposal;
		}
		memset(learner, 0,
		       sizeof(struct learner) 
		       + ps->number * sizeof(struct learned));
		learner->state = INIT;
		pi->learner = learner;
	}

	pi->ps = ps;
	list_add_tail(&pi->list, &ps->pi_head);

	return (pi_handle_t)pi;

out_accepted_proposal:
	if (ps->role[myid] & ACCEPTOR)
		free(acceptor->accepted_proposal);
out_acceptor:
	if (ps->role[myid] & ACCEPTOR)
		free(acceptor);
out_proposal:
	if (ps->role[myid] & PROPOSER)
		free(proposer->proposal);
out_proposer:
	if (ps->role[myid] & PROPOSER)
		free(proposer);
out_prio:
	if (pi->prio)
		free(pi->prio);
out_pi:
	free(pi);
out:
	return rv;
}

int paxos_round_request(pi_handle_t handle,
			void *value,
			void (*end_request) (pi_handle_t handle,
					     int round,
					     int result))
{
	struct paxos_instance *pi = (struct paxos_instance *)handle;
	int myid = pi->ps->p_op->get_myid();
	int round;

	if (!(pi->ps->role[myid] & PROPOSER))
		return -EOPNOTSUPP;

	pi->proposer->state = PREPARING; 
	memcpy(pi->proposer->proposal->value, value, pi->ps->valuelen);

	pi->end = end_request;
	pi->ps->r_op->prepare(pi, &round);

	return round;
}

int paxos_recovery_status_get(pi_handle_t handle)
{	
	struct paxos_instance *pi = (struct paxos_instance *)handle;
	int myid = pi->ps->p_op->get_myid();

	if (!(pi->ps->role[myid] & ACCEPTOR))
		return -EOPNOTSUPP;

	if (pi->acceptor->state == RECOVERY)
		return 1;
	else
		return 0;
}

int paxos_recovery_status_set(pi_handle_t handle, int recovery)
{
	struct paxos_instance *pi = (struct paxos_instance *)handle;
	int myid = pi->ps->p_op->get_myid();

	if (!(pi->ps->role[myid] & ACCEPTOR))
		return -EOPNOTSUPP;

	if (recovery)
		pi->acceptor->state = RECOVERY;
	else
		pi->acceptor->state = INIT;

	return 0;
}

int paxos_propose(pi_handle_t handle, void *value, int round)
{
	struct paxos_instance *pi = (struct paxos_instance *)handle;

	strcpy(pi->proposer->proposal->value, value);
	pi->round = round;

	pi->ps->r_op->propose(pi->ps, pi, NULL, 0);

	return 0;
}

int paxos_recvmsg(void *msg, int msglen)
{
	struct paxos_msghdr *hdr = msg;
	struct paxos_space *ps;
	struct paxos_instance *pi;
	int found = 0;
	int myid;

	list_for_each_entry(ps, &ps_head, list) {
		if (!strcmp(ps->name, hdr->psname)) {
			found = 1;
			break;
		}
	}
	if (!found)
		return -EINVAL;
	myid = ps->p_op->get_myid();

	found = 0;
	list_for_each_entry(pi, &ps->pi_head, list) {
		if (!strcmp(pi->name, hdr->piname)) {
			found = 1;
			break;
		}
	}
	if (!found)
		paxos_instance_init((ps_handle_t)ps, hdr->piname, NULL);

	switch (ntohl(hdr->state)) {
	case PREPARING:
		if (ps->role[myid] & ACCEPTOR)
			ps->a_op->promise(ps, pi, msg, msglen);
		break;
	case PROMISING:
		ps->r_op->propose(ps, pi, msg, msglen);
		break;
	case PROPOSING:
		if (ps->role[myid] & ACCEPTOR)
			ps->a_op->accepted(ps, pi, msg, msglen);
		break;
	case ACCEPTING:
		if (ntohl(hdr->proposer_id) == myid)
			ps->r_op->commit(ps, pi, msg, msglen);
		else if (ps->role[myid] & LEARNER)
			ps->l_op->response(ps, pi, msg, msglen);
		break;
	default:
		break;
	};

	return 0;
}
