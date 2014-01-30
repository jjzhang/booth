/* 
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013-2014 Philipp Marek <philipp.marek@linbit.com>
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

#ifndef _BOOTH_H
#define _BOOTH_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>


#define BOOTH_RUN_DIR "/var/run/booth/"
#define BOOTH_LOG_DIR "/var/log"
#define BOOTH_LOGFILE_NAME "booth.log"
#define BOOTH_DEFAULT_CONF_DIR "/etc/booth/"
#define BOOTH_DEFAULT_CONF_NAME "booth"
#define BOOTH_DEFAULT_CONF_EXT ".conf"
#define BOOTH_DEFAULT_CONF \
	BOOTH_DEFAULT_CONF_DIR BOOTH_DEFAULT_CONF_NAME BOOTH_DEFAULT_CONF_EXT

#define DAEMON_NAME		"boothd"
#define BOOTH_PATH_LEN		127

#define BOOTH_DEFAULT_PORT		9929

/* TODO: remove */
#define BOOTH_PROTO_FAMILY	AF_INET

#define BOOTHC_MAGIC		0x5F1BA08C
#define BOOTHC_VERSION		0x00010002


/** Timeout value for poll().
 * Determines frequency of periodic jobs, eg. when send-retries are done.
 * See process_tickets(). */
#define POLL_TIMEOUT	1000


/** @{ */
/** The on-network data structures and constants. */

#define BOOTH_NAME_LEN		64

#define NO_OWNER (-1)

typedef unsigned char boothc_site  [BOOTH_NAME_LEN];
typedef unsigned char boothc_ticket[BOOTH_NAME_LEN];


struct boothc_header {
	/** Authentication data; not used now. */
	uint32_t iv;
	uint32_t auth1;
	uint32_t auth2;


	/** BOOTHC_MAGIC */
	uint32_t magic;
	/** BOOTHC_VERSION */
	uint32_t version;

	/** Packet source; site_id. See add_site(). */
	uint32_t from;

	/** Length including header */
	uint32_t length;

	/** The command respectively protocol state. See cmd_request_t. */
	uint32_t cmd;
	/** Result of operation. 0 == OK */
	uint32_t result;

	char data[0];
} __attribute__((packed));


struct ticket_msg {
	/** Ticket name. */
	boothc_ticket id;

	/** Owner. May be NO_OWNER. See add_site().  */
	uint32_t owner;

	/** Current ballot number. Might be < prev_ballot if overflown. */
	uint32_t ballot;
	/** Previous ballot. */
	uint32_t prev_ballot;

	/* Would we want to say _whose_ proposal is more important
	 * when sending OP_REJECTED ? */

	/** Seconds until expiration. */
	uint32_t expiry;
} __attribute__((packed));


struct boothc_ticket_msg {
	struct boothc_header header;
	struct ticket_msg ticket;
} __attribute__((packed));


/** State and message IDs.
 *
 * These numbers are unlikely to conflict with other enums.
 * All have to be swabbed to network order before sending.
 * 
 * \dot
 * digraph states {
 *		node [shape=box];
 *		ST_INIT [label="ST_INIT"];
 *
 *		subgraph messages { // messages
 *		rank=same;
 *		node [shape=point, rank=same];
 *		edge [style=tapered, penwidth=3, arrowtail=none, arrowhead=none, dir=forward];
 *
 *		ST_INIT:e -> ST_INITs [label="sends out CMD_CATCHUP"];
 *		}
 *
 *		ST_INIT -> ST_STABLE [label="recv CMR_CATCHUP"];
 *		ST_STABLE;
 *
 *		ST_STABLE -> OP_PROPOSING [label="booth call to assign ticket"];
 * }
 * \enddot
 *
 * */
#define CHAR2CONST(a,b,c,d) ((a << 24) | (b << 16) | (c << 8) | d)
#define STG2CONST(X) ({ const char _ggg[4] = X; return (uint32_t*)_ggg; })
typedef enum {
	/* 0x43 = "C"ommands */
	CMD_LIST    = CHAR2CONST('C', 'L', 's', 't'),
	CMD_GRANT   = CHAR2CONST('C', 'G', 'n', 't'),
	CMD_REVOKE  = CHAR2CONST('C', 'R', 'v', 'k'),
	CMD_CATCHUP = CHAR2CONST('C', 'C', 't', 'p'),

	/* Replies */
	CMR_GENERAL = CHAR2CONST('G', 'n', 'l', 'R'), // Increase distance to CMR_GRANT
	CMR_LIST    = CHAR2CONST('R', 'L', 's', 't'),
	CMR_GRANT   = CHAR2CONST('R', 'G', 'n', 't'),
	CMR_REVOKE  = CHAR2CONST('R', 'R', 'v', 'k'),
	CMR_CATCHUP = CHAR2CONST('R', 'C', 't', 'p'),

	/* Paxos */
	OP_PREPARING = CHAR2CONST('P', 'r', 'e', 'p'),
	OP_PROMISING = CHAR2CONST('P', 'r', 'o', 'm'),
	OP_PROPOSING = CHAR2CONST('P', 'r', 'o', 'p'),
	OP_ACCEPTING = CHAR2CONST('A', 'c', 'p', 't'),
	OP_RECOVERY  = CHAR2CONST('R', 'c', 'v', 'y'),
	OP_COMMITTED = CHAR2CONST('C', 'm', 'm', 't'),
	OP_REJECTED  = CHAR2CONST('R', 'J', 'C', '!'),

	/* These are not used over the wire */
	ST_INIT      = CHAR2CONST('I', 'n', 'i', 't'),
	ST_STABLE    = CHAR2CONST('S', 't', 'b', 'l'),
} cmd_request_t;


/* TODO: make readable constants */
typedef enum {
	/* for compatibility with other functions */
	RLT_SUCCESS             = 0,
	RLT_ASYNC               = CHAR2CONST('A', 's', 'y', 'n'),
	RLT_SYNC_SUCC           = CHAR2CONST('S', 'c', 'c', 's'),
	RLT_SYNC_FAIL           = CHAR2CONST('F', 'a', 'i', 'l'),
	RLT_INVALID_ARG         = CHAR2CONST('I', 'A', 'r', 'g'),
	RLT_OVERGRANT           = CHAR2CONST('O', 'v', 'e', 'r'),
	RLT_PROBABLY_SUCCESS    = CHAR2CONST('S', 'u', 'c', '?'),
	RLT_BUSY                = CHAR2CONST('B', 'u', 's', 'y'),
} cmd_result_t;


/** @} */

/** @{ */

struct booth_site {
	/** Calculated ID. See add_site(). */
	int site_id;
	int type;
	int local;

	/** Roles, like ACCEPTOR, PROPOSER, or LEARNER. Not really used ATM. */
	int role;

	char addr_string[BOOTH_NAME_LEN];

	int tcp_fd;
	int udp_fd;

	/* 0-based, used for indexing into per-ticket weights */
	int index;
	uint64_t bitmask;

	unsigned short family;
	union {
		struct sockaddr_in  sa4;
		struct sockaddr_in6 sa6;
	};
	int saddrlen;
	int addrlen;
} __attribute__((packed));



extern struct booth_site *local;

/** @} */

struct booth_transport;

struct client {
	int fd;
	const struct booth_transport *transport;
	void (*workfn)(int);
	void (*deadfn)(int);
};

extern struct client *clients;
extern struct pollfd *pollfds;


int client_add(int fd, const struct booth_transport *tpt,
		void (*workfn)(int ci), void (*deadfn)(int ci));
int do_read(int fd, void *buf, size_t count);
int do_write(int fd, void *buf, size_t count);
void process_connection(int ci);
void safe_copy(char *dest, char *value, size_t buflen, const char *description);


#endif /* _BOOTH_H */
