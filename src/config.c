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
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>
#include "booth.h"
#include "config.h"
#include "ticket.h"
#include "log.h"

static int ticket_size = 0;

static int ticket_realloc(void)
{
	const int added = 5;
	int had, want;
	void *p;

	had = booth_conf->ticket_allocated;
	want = had + added;

	p = realloc(booth_conf->ticket,
			sizeof(struct ticket_config) * want);
	if (!booth_conf) {
		log_error("can't alloc more tickets");
		return -ENOMEM;
	}

	memset(booth_conf->ticket + had, 0,
			sizeof(struct ticket_config) * added);
	booth_conf->ticket_allocated = want;
	booth_conf->ticket = p;

	return 0;
}


int add_node(char *address, int type);
int add_node(char *addr_string, int type)
{
	int rv;
	struct booth_site *node;
	uLong nid;
	uint32_t mask;


	rv = 1;
	if (booth_conf->node_count == MAX_NODES) {
		log_error("too many nodes");
		goto out;
	}
	if (strlen(addr_string)+1 >= sizeof(booth_conf->node[0].addr_string)) {
		log_error("node address \"%s\" too long", addr_string);
		goto out;
	}

	node = booth_conf->node + booth_conf->node_count;

	node->family = BOOTH_PROTO_FAMILY;
	node->type = type;
	/* Make nodeid start at a non-zero point.
	 * Perhaps use hash over string or address? */
	strcpy(node->addr_string, addr_string);

	nid = crc32(0L, NULL, 0);
	/* booth_config() uses memset(), so sizeof() is guaranteed to give
	 * the same result everywhere - no uninitialized bytes. */
	node->nodeid = crc32(nid, node->addr_string,
			sizeof(node->addr_string));
	/* Make sure we will never collide with NO_OWNER,
	 * or be negative (to get "get_local_id() < 0" working). */
	mask = 1 << (sizeof(node->nodeid)*4 -1);
	assert(NO_OWNER & mask);
	assert(NO_OWNER >= 0);
	node->nodeid &= ~mask;


	node->tcp_fd = -1;

	if (node->type == SITE)
		node->role = PROPOSER | ACCEPTOR | LEARNER;
	else if (node->type == ARBITRATOR)
		node->role = ACCEPTOR | LEARNER;


	booth_conf->node_count++;

	rv = 0;
	memset(&node->sa6, 0, sizeof(node->sa6));

	if (inet_pton(AF_INET,
				node->addr_string,
				&node->sa4.sin_addr) > 0) {

		node->family = AF_INET;
		node->sa4.sin_family = node->family;
		node->sa4.sin_port = htons(booth_conf->port);
		node->saddrlen = sizeof(node->sa4);
		node->addrlen = sizeof(node->sa4.sin_addr);

	} else if (inet_pton(AF_INET6,
				node->addr_string,
				&node->sa6.sin6_addr) > 0) {

		node->family = AF_INET6;
		node->sa6.sin6_family = node->family;
		node->sa6.sin6_flowinfo = 0;
		node->sa6.sin6_port = htons(booth_conf->port);
		node->saddrlen = sizeof(node->sa6);
		node->addrlen = sizeof(node->sa6.sin6_addr);

	} else {
		log_error("Address string \"%s\" is bad", node->addr_string);
		rv = EINVAL;
	}

out:
	return rv;
}


static int add_ticket(const char *name, struct ticket_config **tkp,
		int expiry, int weights[MAX_NODES])
{
	int rv;
	struct ticket_config *tk;

	if (booth_conf->ticket_count == booth_conf->ticket_allocated) {
		rv = ticket_realloc();
		if (rv < 0)
			return rv;
	}


	tk = booth_conf->ticket + booth_conf->ticket_count;
	booth_conf->ticket_count++;


	if (!check_max_len_valid(name, sizeof(tk->name))) {
		log_error("ticket name \"%s\" too long.", name);
		return -EINVAL;
	}

	strcpy(tk->name, name);
	tk->expiry = expiry;
	memcpy(tk->weight, weights, sizeof(tk->weight));
	tk->current_state.state = OP_INIT;

	if (tkp)
		*tkp = tk;
	return 0;
}


inline static char *skip_while(char *cp, int (*fn)(int))
{
	while (fn(*cp))
		cp++;
	return cp;
}

inline static char *skip_until(char *cp, char expected)
{
	while (*cp && *cp != expected)
		cp++;
	return cp;
}


static inline int is_end_of_line(char *cp)
{
	char c = *cp;
	return c == '\n' || c == 0 || c == '#';
}


/* returns number of weights, or -1 on bad input. */
static int parse_weights(const char *input, int weights[MAX_NODES])
{
	int i, v;
	char *cp;

	for(i=0; i<MAX_NODES; i++) {
		/* End of input? */
		if (*input == 0)
			break;

		v = strtol(input, &cp, 0);
		if (input == cp) {
			log_error("No integer weight value at \"%s\"", input);
			return -1;
		}

		while (*cp) {
			/* Separator characters */
			if (isspace(*cp) ||
					strchr(",;:-+", *cp))
				cp++;
			/* Next weight */
			else if (isdigit(*cp))
				break;
			/* Rest */
			else {
				log_error("Invalid character at \"%s\"", cp);
				return -1;
			}
		}

		input = cp;
	}


	/* Fill rest of vector. */
	for(v=i; v<MAX_NODES; v++) {
		weights[v] = 1;
	}

	return i;
}


int read_config(const char *path)
{
	char line[1024];
	FILE *fp;
	char *s, *key, *val, *end_of_key;
	const char *cp, *error;
	int i;
	int lineno = 0;
	int got_transport = 0;
	int def_expire = DEFAULT_TICKET_EXPIRY;
	int weights[MAX_NODES];
	struct ticket_config *last_ticket = NULL;


	fp = fopen(path, "r");
	if (!fp) {
		log_error("failed to open %s: %s", path, strerror(errno));
		return -1;
	}

	booth_conf = malloc(sizeof(struct booth_config)
			+ TICKET_ALLOC * sizeof(struct ticket_config));
	if (!booth_conf) {
		log_error("failed to alloc memory for booth config");
		return -ENOMEM;
	}
	memset(booth_conf, 0, sizeof(struct booth_config)
			+ TICKET_ALLOC * sizeof(struct ticket_config));
	ticket_size = TICKET_ALLOC;

	booth_conf->proto = UDP;
	parse_weights("", weights);
	error = "";

	log_debug("reading config file %s", path);
	while (fgets(line, sizeof(line), fp)) {
		lineno++;

		s = skip_while(line, isspace);
		if (is_end_of_line(s))
			continue;
		key = s;


		/* Key */
		end_of_key = skip_while(key, isalnum);
		if (end_of_key == key) {
			error = "No key";
			goto err;
		}

		if (!*end_of_key)
			goto exp_equal;


		/* whitespace, and something else but nothing more? */
		s = skip_while(end_of_key, isspace);


		if (*s != '=') {
exp_equal:
			error = "Expected '=' after key";
			goto err;
		}
		s++;

		/* It's my buffer, and I terminate if I want to. */
		/* But not earlier than that, because we had to check for = */
		*end_of_key = 0;


		/* Value tokenizing */
		s = skip_while(s, isspace);
		switch (*s) {
			case '"':
			case '\'':
				val = s+1;
				s = skip_until(val, *s);
				/* Terminate value */
				if (!*s) {
					error = "Unterminated quoted string";
					goto err;
				}

				/* Remove and skip quote */
				*s = 0;
				s++;
				if (* skip_while(s, isspace)) {
					error = "Surplus data after value";
					goto err;
				}

				*s = 0;

				break;

			case 0:
no_value:
				error = "No value";
				goto err;
				break;

			default:
				val = s;
				/* Rest of line. */
				i = strlen(s);
				/* i > 0 because of "case 0" above. */
				while (i > 0 && isspace(s[i-1]))
					i--;
				s += i;
				*s = 0;
		}

		if (val == s)
			goto no_value;


		if (strlen(key) > BOOTH_NAME_LEN
				|| strlen(val) > BOOTH_NAME_LEN) {
			error = "key/value too long";
			goto err;
		}

		if (strcmp(key, "transport") == 0) {
			if (got_transport) {
				error = "config file has multiple transport lines";
				goto err;
			}

			if (strcasecmp(val, "UDP") == 0)
				booth_conf->proto = UDP;
			else if (strcasecmp(val, "SCTP") == 0)
				booth_conf->proto = SCTP;
			else {
				error = "invalid transport protocol";
				goto err;
			}
			got_transport = 1;
		}

		if (strcmp(key, "port") == 0)
			booth_conf->port = atoi(val);

		if (strcmp(key, "name") == 0) {
			if(strlen(val)+1 >= BOOTH_NAME_LEN) {
				error = "Config name too long.";
				goto err;
			}
		}

		if (strcmp(key, "site") == 0) {
			if (add_node(val, SITE))
				goto out;
		}

		if (strcmp(key, "arbitrator") == 0) {
			if (add_node(val, ARBITRATOR))
				goto out;
		}

		if (strcmp(key, "ticket") == 0) {
			if (add_ticket(val, &last_ticket,
						def_expire, weights))
				goto out;

			/* last_ticket is valid until another one is needed -
			 * and then it already has the new address and
			 * is valid again. */
		}

		if (strcmp(key, "expire") == 0) {
			def_expire = strtol(val, &s, 0);
			if (*s || s == val) {
				error = "Expected plain integer value for expire";
				goto err;
			}

			if (last_ticket)
				last_ticket->expiry = def_expire;
		}

		if (strcmp(key, "weights") == 0) {
			if (parse_weights(val, weights) < 0)
				goto out;

			if (last_ticket)
				memcpy(last_ticket->weight, weights,
						sizeof(last_ticket->weight));
		}
	}


	/* Default: make config name match config filename. */
	if (!booth_conf->name[0]) {
		cp = strrchr(path, '/');
		if (!cp)
			cp = path;

		/* TODO: locale? */
		/* NUL-termination by memset. */
		for(i=0; i<BOOTH_NAME_LEN-1 && isalnum(*cp); i++)
			booth_conf->name[i] = *(cp++);

		/* Last resort. */
		if (!booth_conf->name[0])
			strcpy(booth_conf->name, "booth");
	}

	return 0;


err:
out:
	log_error("%s in config file line %d",
			error, lineno);

	free(booth_conf);
	booth_conf = NULL;
	return -1;
}

int check_config(int type)
{
	if (!booth_conf)
		return -1;

	return 0;
}


int find_site_in_config(unsigned char *site, struct booth_site **node)
{
	struct booth_site *n;
	int i;

	if (!booth_conf)
		return 0;

	for (i = 0; i < booth_conf->node_count; i++) {
		n = booth_conf->node + i;
		if (n->type == SITE &&
		    strcmp(n->addr_string, site) == 0) {
			*node = n;
			return 1;
		}
	}

	return 0;
}

int find_nodeid_in_config(uint32_t nodeid, struct booth_site **node)
{
	struct booth_site *n;
	int i;

	if (nodeid == NO_OWNER) {
		*node = NULL;
		return 1;
	}

	if (!booth_conf)
		return 0;

	for (i = 0; i < booth_conf->node_count; i++) {
		n = booth_conf->node + i;
		if (n->nodeid == nodeid) {
			*node = n;
			return 1;
		}
	}

	return 0;
}



const char *type_to_string(int type)
{
	switch (type)
	{
		case ARBITRATOR: return "arbitrator";
		case SITE:       return "site";
		case CLIENT:     return "client";
	}
	return "??invalid-type??";
}
