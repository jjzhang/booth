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
#include <errno.h>
#include <string.h>
#include "booth.h"
#include "config.h"
#include "ticket.h"
#include "log.h"

static int ticket_size = 0;

static int ticket_realloc(void)
{
	void *p;

	booth_conf = realloc(booth_conf, sizeof(struct booth_config)
					 + (ticket_size + TICKET_ALLOC)
					 * sizeof(struct ticket_config));
	if (!booth_conf) {
		log_error("can't alloc more booth config");
		return -ENOMEM;
	}

	p = (char *) booth_conf + sizeof(struct booth_config)
	    + ticket_size * sizeof(struct ticket_config);
	memset(p, 0, TICKET_ALLOC * sizeof(struct ticket_config));
	ticket_size += TICKET_ALLOC;

	return 0;
}


int add_node(char *address, int type);
int add_node(char *addr_string, int type)
{
	int rv;
	struct booth_node *node;

	rv = 1;
	if (booth_conf->node_count == MAX_NODES) {
		log_error("too many nodes");
		goto out;
	}
	if (strlen(addr_string)+1 >= sizeof(booth_conf->node[0].addr_string)) {
		log_error("node address \"%s\" too long", addr_string);
		goto out;
	}

	node = booth_conf->node+booth_conf->node_count;

	node->family = BOOTH_PROTO_FAMILY;
	node->type = type;
	node->nodeid = booth_conf->node_count;
	strcpy(node->addr_string, addr_string);
	node->tcp_fd = -1;

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


int read_config(const char *path)
{
	char line[1024];
	FILE *fp;
	char *s, *key, *val, *expiry, *weight, *c, *end_of_key;
	const char *cp, *error;
	int i;
	int lineno = 0;
	int got_transport = 0;

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
			int count = booth_conf->ticket_count;
			if (booth_conf->ticket_count == ticket_size) {
				if (ticket_realloc() < 0)
					goto out;
			}
			expiry = index(val, ';');
			weight = rindex(val, ';');
			if (!expiry) {
				strcpy(booth_conf->ticket[count].name, val);
				booth_conf->ticket[count].expiry = DEFAULT_TICKET_EXPIRY;
				log_info("expire is not set in %s."
						" Set the default value %ds.",
						booth_conf->ticket[count].name,
						DEFAULT_TICKET_EXPIRY);
			}
			else if (expiry && expiry == weight) {
				*expiry++ = '\0';
				while (*expiry == ' ')
					expiry++;
				strcpy(booth_conf->ticket[count].name, val);
				booth_conf->ticket[count].expiry = atoi(expiry);
			} else {
				*expiry++ = '\0';
				*weight++ = '\0';
				while (*expiry == ' ')
					expiry++;
				while (*weight == ' ')
					weight++;
				strcpy(booth_conf->ticket[count].name, val);
				booth_conf->ticket[count].expiry = atoi(expiry);
				i = 0;
				while ((c = index(weight, ','))) {
					*c++ = '\0';
					booth_conf->ticket[count].weight[i++]
						= atoi(weight);
					while (*c == ' ')
						c++;
					weight = c;
					if (i == MAX_NODES) {
						error = "too many weights";
						goto err;
					}
				}
			}
			booth_conf->ticket_count++;
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
	log_error("%s in config file line %d",
			error, lineno);

out:
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


int find_site_in_config(unsigned char *site, struct booth_node **node)
{
	struct booth_node *n;
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
