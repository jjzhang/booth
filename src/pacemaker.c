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

#include <stdio.h>
#include "log.h"
#include "pacemaker.h"

#define COMMAND_MAX	256

static void pcmk_grant_ticket(const char *ticket)
{
	FILE *p;
	char cmd[COMMAND_MAX];

	snprintf(cmd, COMMAND_MAX, "crm_ticket -t %s -g --force",
		 (char *)ticket);
	log_info("command: '%s' was executed", cmd);
	p = popen(cmd, "r");
	if (p == NULL) {
		log_error("popen error: %s", cmd);
		return;
	}
	pclose(p);

	return;
}

static void pcmk_revoke_ticket(const char *ticket)
{
	FILE *p;
	char cmd[COMMAND_MAX];

	snprintf(cmd, COMMAND_MAX, "crm_ticket -t %s -r --force",
		 (char *)ticket);
	log_info("command: '%s' was executed", cmd);
	p = popen(cmd, "r");
	if (p == NULL) {
		log_error("popen error: %s", cmd);
		return;
	}
	pclose(p);

	return;
}

static void pcmk_store_ticket(const char* ticket,
		uint32_t owner, uint32_t ballot,
		time_t expires)
{
	FILE *p;
	char cmd[COMMAND_MAX];

	snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t %s -S owner -v %d",
		 (char *)ticket, owner);
	log_info("command: '%s' was executed", cmd);
	p = popen(cmd, "r");
	if (p == NULL) {
		log_error("popen error: %s", cmd);
		return;
	}
	pclose(p);

	snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t %s -S expires -v %llu",
		 (char *)ticket, (unsigned long long)expires);
	log_info("command: '%s' was executed", cmd);
	p = popen(cmd, "r");
	if (p == NULL) {
		log_error("popen error: %s", cmd);
		return;
	}
	pclose(p);

	snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t %s -S ballot -v %d",
		 (char *)ticket, ballot);
	log_info("command: '%s' was executed", cmd);
	p = popen(cmd, "r");
	if (p == NULL) {
		log_error("popen error: %s", cmd);
		return;
	}
	pclose(p);

	return;
}

static void pcmk_load_ticket(const char *ticket,
		uint32_t *owner, uint32_t *ballot,
		time_t *expires)
{
	FILE *p;
	char cmd[COMMAND_MAX];
	char line[256];
	int ow, ba;
	unsigned long long ex;

	snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t %s -G owner --quiet",
		 (char *)ticket);
	log_info("command: '%s' was executed", cmd);
	p = popen(cmd, "r");
	if (p == NULL) {
		log_error("popen error: %s", cmd);
		return;
	}
	if (fgets(line, sizeof(line) - 1, p) == NULL) {
		pclose(p);
		return;
	}
	if (sscanf(line, "%d", &ow) == 1)
		*owner = ow;
	pclose(p);
	
	snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t %s -G expires --quiet",
		 (char *)ticket);
	log_info("command: '%s' was executed", cmd);
	p = popen(cmd, "r");
	if (p == NULL) {
		log_error("popen error: %s", cmd);
		return;
	}
	if (fgets(line, sizeof(line) - 1, p) == NULL) {
		pclose(p);
		return;
	}
	if (sscanf(line, "%llu", &ex) == 1)
		*expires = ex;
	pclose(p);

	snprintf(cmd, COMMAND_MAX,
		 "crm_ticket -t %s -G ballot --quiet",
		 (char *)ticket);
	log_info("command: '%s' was executed", cmd);
	p = popen(cmd, "r");
	if (p == NULL) {
		log_error("popen error: %s", cmd);
		return;
	}
	if (fgets(line, sizeof(line) - 1, p) == NULL) {
		pclose(p);
		return;
	}
	if (sscanf(line, "%d", &ba) == 1)
		*ballot = ba;
	pclose(p);

	return;
}

struct ticket_handler pcmk_handler = {
	.grant_ticket   = pcmk_grant_ticket,
	.revoke_ticket  = pcmk_revoke_ticket,
	.store_ticket   = pcmk_store_ticket,
	.load_ticket    = pcmk_load_ticket,
};
