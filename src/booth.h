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

#ifndef _BOOTH_H
#define _BOOTH_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* TODO: Remove */
#define BOOTH_LOG_DUMP_SIZE (1024*1024)

#define BOOTH_RUN_DIR "/var/run/booth/"
#define BOOTH_LOG_DIR "/var/log"
#define BOOTH_LOGFILE_NAME "booth.log"
#define BOOTH_DEFAULT_CONF "/etc/booth/booth.conf"

#define DAEMON_NAME		"booth"
#define BOOTH_PATH_LEN		127

/* TODO: remove */
#define BOOTH_PROTO_FAMILY	AF_INET

#define BOOTHC_MAGIC		0x5F1BA08C
#define BOOTHC_VERSION		0x00010002


/** @{ */
/** The on-network data structures and constants. */

#define BOOTH_NAME_LEN		64

#define NO_OWNER (-1)

typedef unsigned char boothc_site  [BOOTH_NAME_LEN];
typedef unsigned char boothc_ticket[BOOTH_NAME_LEN];


struct boothc_header {
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

	/** Seconds until expiration. */
	uint32_t expiry;

#if 0
	/* From lease - not needed? */
	uint32_t clear; /* NOT_CLEAR_RELEASE ? */
	uint32_t leased;  /* has_been_leased by another node? */


	/* needed?? */
	/* From lease */
	uint32_t op; /* OP_START_LEASE, OP_STOP_LEASE? ?*/
#endif
} __attribute__((packed));


struct boothc_ticket_msg {
	struct boothc_header header;
	struct ticket_msg ticket;
} __attribute__((packed));


/* Use numbers that are unlikely to conflict with other enums.
 * All these have to be swabbed to network order before sending. */
typedef enum {
	/* 0x43 = "C"ommands */
	CMD_LIST    = 0x436f6d4c,
	CMD_GRANT   = 0x436f6d47,
	CMD_REVOKE  = 0x436f6d52,
	CMD_CATCHUP = 0x436f6d43,

	/* Replies */
	CMR_GENERAL = 0x436f5267,
	CMR_LIST    = 0x436f524c,
	CMR_GRANT   = 0x436f5247,
	CMR_REVOKE  = 0x436f5252,
	CMR_CATCHUP = 0x436f5243,

	/* 0x50 = "P"axos */
	OP_INIT      = 0x50617801,
	OP_PREPARING,
	OP_PROMISING,
	OP_PROPOSING,
	OP_ACCEPTING,
	OP_RECOVERY,
	OP_COMMITTED,
	OP_REJECTED,
} cmd_request_t;


typedef enum {
	/* for compatibility with other functions */
	RLT_SUCCESS = 0,
	RLT_ASYNC = 0x526c5401,
	RLT_SYNC_SUCC,
	RLT_SYNC_FAIL,
	RLT_INVALID_ARG,
	RLT_REMOTE_OP,
	RLT_OVERGRANT,
} cmd_result_t;


/** @} */

/** @{ */

struct booth_site {
	/** Calculated ID. See add_site(). */
	int site_id;
	int type;
	int local;

	int role;

	char addr_string[BOOTH_NAME_LEN];

	int tcp_fd;

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
