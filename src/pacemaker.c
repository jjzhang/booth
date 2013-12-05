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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include "log.h"
#include "pacemaker.h"
#include "inline-fn.h"

#define COMMAND_MAX	256

static void pcmk_grant_ticket(struct ticket_config *tk)
{
	char cmd[COMMAND_MAX];
	int rv;

	snprintf(cmd, COMMAND_MAX, "crm_ticket -t %s -g --force",
			tk->name);
	log_info("command: '%s' was executed", cmd);
	rv = system(cmd);
	if (rv != 0)
		log_error("error: \"%s\" failed, rv %d", cmd, rv);
}

static void pcmk_revoke_ticket(struct ticket_config *tk)
{
	char cmd[COMMAND_MAX];
	int rv;

	snprintf(cmd, COMMAND_MAX, "crm_ticket -t %s -r --force",
			tk->name);
	log_info("command: '%s' was executed", cmd);
	rv = system(cmd);
	if (rv != 0)
		log_error("error: \"%s\" failed, rv %d", cmd, rv);
}


static int crm_ticket_set(const struct ticket_config *tk, const char *attr, int64_t val)
{
	char cmd[COMMAND_MAX];
	int i, rv;


	snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t '%s' -S '%s' -v %" PRIi64,
		 tk->name, attr, val);
	/* If there are errors, there's not much we can do but retry ... */
	for (i=0; i<3 &&
			(rv = system(cmd));
			i++) ;

	log_info("'%s' gave result %d", cmd, rv);

	return rv;
}


static void pcmk_store_ticket(struct ticket_config *tk)
{
	crm_ticket_set(tk, "owner", get_node_id(tk->current_state.owner));
	crm_ticket_set(tk, "expires", tk->current_state.expires);
	crm_ticket_set(tk, "ballot", tk->current_state.ballot);
}


static int crm_ticket_get(struct ticket_config *tk,
		const char *attr, int64_t *data)
{
	char cmd[COMMAND_MAX];
	char line[256];
	int rv;
	int64_t v;
	FILE *p;


	*data = -1;
	v = 0;
	snprintf(cmd, COMMAND_MAX,
			"crm_ticket -t '%s' -G '%s' --quiet",
			tk->name, attr);

	p = popen(cmd, "r");
	if (p == NULL) {
		rv = errno;
		log_error("popen error %d (%s) for \"%s\"",
				rv, strerror(rv), cmd);
		return rv || -EINVAL;
	}
	if (fgets(line, sizeof(line) - 1, p) == NULL) {
		rv = ENODATA;
		goto out;
	}

	rv = EINVAL;
	if (sscanf(line, "%" PRIi64, &v) == 1)
		rv = 0;

	*data = v;

out:
	rv = pclose(p);
	log_info("command \"%s\" returned rv %d, value %" PRIi64, cmd, rv, v);
	return rv;
}


static void pcmk_load_ticket(struct ticket_config *tk)
{
	int rv;
	int64_t v;
	time_t now;
	struct ticket_paxos_state *tps;


	rv = crm_ticket_get(tk, "expires", &v);
	if (!rv) {
		tk->proposed_state.expires = v;
	}

	rv = crm_ticket_get(tk, "ballot", &v);
	if (!rv) {
		tk->proposed_state.ballot =
			tk->proposed_state.prev_ballot = v;
	}

	rv = crm_ticket_get(tk, "owner", &v);
	if (!rv) {
		/* No check, node could have been deconfigured. */
		find_site_by_id(v, &tk->proposed_state.owner);
	}


	time(&now);
	tps = &tk->proposed_state;
	if (now >= tps->expires ||
			!tps->owner) {
		tps->owner = NULL;
		tps->expires = 0;
	}

	tps->acknowledges = local->bitmask;

	/* We load only when the state is completely unknown,
	 * so make that current, too. */
	tk->current_state = tk->proposed_state;

	return;
}

struct ticket_handler pcmk_handler = {
	.grant_ticket   = pcmk_grant_ticket,
	.revoke_ticket  = pcmk_revoke_ticket,
	.store_ticket   = pcmk_store_ticket,
	.load_ticket    = pcmk_load_ticket,
};
