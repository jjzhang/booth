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
#define BOOTH_NAME_LEN		63
#define BOOTH_PATH_LEN		127

/* TODO: remove */
#define BOOTH_PROTO_FAMILY	AF_INET

#define BOOTHC_MAGIC		0x5F1BA08C
#define BOOTHC_VERSION		0x00010002


struct boothc_header {
	/** BOOTHC_MAGIC */
	uint32_t magic;
	/** BOOTHC_VERSION */
	uint32_t version;

	/** Packet source; nodeid. See add_node(). */
	uint32_t from;

	/** Length including header */
	uint32_t length;

	/** The command, see cmd_request_t. cmp paxos_state_t ?? */
	uint32_t cmd;
	/** Result of operation. 0 == OK */
	uint32_t result;

	char data[0];
} __attribute__((packed));


typedef unsigned char boothc_site  [BOOTH_NAME_LEN];
typedef unsigned char boothc_ticket[BOOTH_NAME_LEN];

struct booth_node {
	int nodeid;
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


extern struct booth_node *local;

inline static int booth_get_myid(void)
{
	return local ? local->nodeid : -1;
}


struct ticket_data {
	/** Ticket name. */
	boothc_ticket id;

	/** Owner. May be NO_OWNER. See add_node().  */
	uint32_t owner;
	/* Better use that? but from is an int currently, too */
	boothc_site owner;

	/** POSIX timestamp? Or time until expiration? */
	uint32_t expiry;

	/* needed?? */
	/* From lease */
	uint32_t op; /* OP_START_LEASE, OP_STOP_LEASE? ?*/
} __attribute__((packed));


struct paxos_control_data {
	/** Current protocol state. See paxos_state_t. */
	uint32_t state;

	/** Current ballot number. Might be < prev_ballot if overflown. */
	uint32_t ballot;
	/** Previous ballot. */
	uint32_t prev_ballot;


	/* From lease - needed? */
	uint32_t clear; /* NOT_CLEAR_RELEASE ? */
	uint32_t leased;  /* has_been_leased by another node? */
};

struct paxos_control_data {

struct site_msg {
	boothc_site site;
};

struct boothc_ticket_site_msg {
	struct boothc_header header;
	struct ticket_msg ticket;
	struct site_msg site;
} __attribute__((packed));

struct boothc_ticket_msg {
	struct boothc_header header;
	struct ticket_msg ticket;
} __attribute__((packed));


struct ticket_data {
};


typedef enum {
	BOOTHC_CMD_LIST = 0x30,
	BOOTHC_CMD_GRANT,
	BOOTHC_CMD_REVOKE,
	BOOTHC_CMD_CATCHUP,
} cmd_request_t;

typedef enum {
	BOOTHC_RLT_ASYNC = 0x40,
	BOOTHC_RLT_SYNC_SUCC,
	BOOTHC_RLT_SYNC_FAIL,
	BOOTHC_RLT_INVALID_ARG,
	BOOTHC_RLT_REMOTE_OP,
	BOOTHC_RLT_OVERGRANT,
} cmd_result_t;

struct client {
        int fd;
        void (*workfn)(int);
        void (*deadfn)(int);
};

int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci));
int do_read(int fd, void *buf, size_t count);
int do_write(int fd, void *buf, size_t count);
void process_connection(int ci);
void safe_copy(char *dest, char *value, size_t buflen, const char *description);



static inline void init_header(struct boothc_header *h, int cmd,
			int result, int data_len)
{
	h->magic   = htonl(BOOTHC_MAGIC);
	h->version = htonl(BOOTHC_VERSION);
	h->length  = htonl(data_len);
	h->cmd     = htonl(cmd);
	h->from    = htonl(local->nodeid);
	h->expiry  = htonl(0);
	h->result  = htonl(result);
}

static inline void init_ticket_site_header(struct boothc_ticket_site_msg *msg, int cmd)
{
	init_header(&msg->header, cmd, 0, sizeof(*msg));
}

static inline void init_ticket_msg(struct boothc_ticket_msg *msg, int cmd)
{
	init_header(&msg->header, cmd, 0, sizeof(*msg));
	memset(&msg->ticket, 0, sizeof(msg->ticket));
}


static inline void init_ticket_site_msg(struct boothc_ticket_site_msg *msg, int cmd)
{
	init_ticket_site_header(msg, cmd);
	memset(&msg->site, 0, sizeof(msg->site));
	memset(&msg->ticket, 0, sizeof(msg->ticket));
}


#endif /* _BOOTH_H */
