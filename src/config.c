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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "booth.h"
#include "config.h"
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

	p = booth_conf + sizeof(struct booth_config)
	    + ticket_size * sizeof(struct ticket_config);
	memset(p, 0, TICKET_ALLOC * sizeof(struct ticket_config));
	ticket_size += TICKET_ALLOC;

	return 0;
}

int read_config(const char *path)
{
	char line[1024];
	FILE *fp;
	char *s, *k, *v, *e, *w, *c;
	int quo, equ, ischar, i;
	int lineno = 0;

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

	while (fgets(line, sizeof(line), fp)) {
		lineno++;
		s = line;
		while (*s == ' ')
			s++;
		if (*s == '#' || *s == '\n')
			continue;
		if (*s == '-' || *s == '.' || *s =='/'
		    || *s == '+' || *s == '(' || *s == ')'
		    || *s == ':' || *s == ',' || *s == '@'
		    || *s == '=' || *s == '"') {
			log_error("invalid key name in config file "
				  "('%c', lineno %d)", *s, lineno);
			goto out;
		}
		k = s;
		v = NULL;
		quo = 0;
		equ = 0;
		ischar = 0;
		while (*s != '\n') {
			if (!(*s >='a' && *s <= 'z')
			     && !(*s >= 'A' && *s <= 'Z')
			     && !(*s >= '0' && *s <= '9')
			     && !(*s == '_')
			     && !(*s == '-')
			     && !(*s == '.')
			     && !(*s == '/')
			     && !(*s == ' ')
			     && !(*s == '+')
			     && !(*s == '(')
			     && !(*s == ')')
			     && !(*s == ':')
			     && !(*s == ',')
			     && !(*s == '@')
			     && !(*s == '=')
			     && !(*s == '"')) {
				log_error("invalid character ('%c', lineno %d)"
					  " in config file", *s, lineno);
				goto out;
			}
			if (*s == '=' && !equ) {
				equ = 1;
				*s = '\0';
				v = s + 1;
			} else if (*s == '=' && equ && !quo) {
				log_error("invalid config file format "
					  "(lineno %d)", lineno);
				goto out;
			} else if ((*s == '_' || *s == '-' || *s == '.')
				    && equ && !quo) {
				log_error("invalid config file format "
					  "(lineno %d)", lineno);
				goto out;
			} else if ((*s == '/' || *s == ' ' || *s == '+'
				    || *s == '(' || *s == ')' || *s == ':'
				    || *s == ',' || *s == '@') && !quo) {
				log_error("invalid config file format "
					  "(lineno %d)", lineno);
				goto out;
			} else if (*s == '"' && !equ) {
				log_error("invalid config file format "
					  "(lineno %d)", lineno);
				goto out;
			} else if (*s == '"' && !quo) {
				quo = 1;
				if (v) {
					v++;
					ischar = 1;
				}
			} else if (*s == '"' && quo) {
				quo = 0;
				*s = '\0';
			}
			s++;		 
		}
		if (!equ || quo) {
			log_error("invalid config file format (lineno %d)",
				  lineno);
			goto out;
		}
		if (!ischar)
			*s = '\0';

		if (strlen(k) > BOOTH_NAME_LEN
		    || strlen(v) > BOOTH_NAME_LEN) {
			log_error("key/value too long");
			goto out;
		}

		if (!strcmp(k, "transport")) {
			if (!strcmp(v, "UDP"))
				booth_conf->proto = UDP;
			else if (!strcmp(v, "SCTP"))
				booth_conf->proto = SCTP;
			else {
				log_error("invalid transport protocol");
				goto out;
			}	
		}

		if (!strcmp(k, "port"))
			booth_conf->port = atoi(v);

		if (!strcmp(k, "site")) {
			if (booth_conf->node_count == MAX_NODES) {
				log_error("too many nodes");
				goto out;
			}
			booth_conf->node[booth_conf->node_count].family =
				BOOTH_PROTO_FAMILY;
			booth_conf->node[booth_conf->node_count].type = SITE;
			booth_conf->node[booth_conf->node_count].nodeid = 
				booth_conf->node_count;
			strcpy(booth_conf->node[booth_conf->node_count++].addr,
				v);
		}
		
		if (!strcmp(k, "arbitrator")) {
			if (booth_conf->node_count == MAX_NODES) {
				log_error("too many nodes");
				goto out;
			}
			booth_conf->node[booth_conf->node_count].family =
				BOOTH_PROTO_FAMILY;
			booth_conf->node[booth_conf->node_count].type =
				ARBITRATOR;
			booth_conf->node[booth_conf->node_count].nodeid = 
				booth_conf->node_count;
			strcpy(booth_conf->node[booth_conf->node_count++].addr,
				v);
		}

		if (!strcmp(k, "ticket")) {
			int count = booth_conf->ticket_count;
			if (booth_conf->ticket_count == ticket_size) {
				if (ticket_realloc() < 0)
					goto out;
			}
			e = index(v, ';');
			w = rindex(v, ';');
			if (!e)
				strcpy(booth_conf->ticket[count].name, v);
			else if (e && e == w) {
				*e++ = '\0';
				while (*e == ' ')
					e++;
				strcpy(booth_conf->ticket[count].name, v);
				booth_conf->ticket[count].expiry = atoi(e);
			} else {
				*e++ = '\0';
				*w++ = '\0';
				while (*e == ' ')
					e++;
				while (*w == ' ')
					w++;
				strcpy(booth_conf->ticket[count].name, v);
				booth_conf->ticket[count].expiry = atoi(e);
				i = 0;
				while ((c = index(w, ','))) {
					*c++ = '\0';
					booth_conf->ticket[count].weight[i++]
						= atoi(w);
					while (*c == ' ')
						c++;
					w = c;
					if (i == MAX_NODES) {
						log_error("too many weights");
						break;
					}
				}
			}
			booth_conf->ticket_count++;
		}
	}
	return 0;

out:
	free(booth_conf);
	return -1;
}

int check_config(int type)
{
//	int i;

	if (!booth_conf)
		return -1;

/*	for (i = 0; i < booth_conf->node_count; i++) {
		if (booth_conf->node[i].local && booth_conf->node[i].type ==
			type)
			return 0;
	}

	return -1;*/
	return 0;
}
