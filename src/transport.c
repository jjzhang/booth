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

#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <asm/types.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include "list.h"
#include "booth.h"
#include "inline-fn.h"
#include "log.h"
#include "config.h"
#include "paxos_lease.h"
#include "transport.h"

#define BOOTH_IPADDR_LEN	(sizeof(struct in6_addr))

#define NETLINK_BUFSIZE		16384
#define SOCKET_BUFFER_SIZE	160000
#define FRAME_SIZE_MAX		10000

extern struct client *client;
extern struct pollfd *pollfd;

struct booth_site *local = NULL;

struct tcp_conn {
	int s;
	struct sockaddr to;
	struct list_head list;
};

static LIST_HEAD(tcp);

struct udp_context {
	int s;
	struct iovec iov_recv;
	char iov_buffer[FRAME_SIZE_MAX];
} udp;

static int (*deliver_fn) (void *msg, int msglen);


static void parse_rtattr(struct rtattr *tb[],
			 int max, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
}


static int find_address(unsigned char ipaddr[BOOTH_IPADDR_LEN],
		int family, int prefixlen,
		int fuzzy_allowed,
		struct booth_site **me)
{
	int i;
	struct booth_site *node;
	int bytes, bits_left, mask;
	unsigned char node_bits, ip_bits;
	uint8_t *n_a;


	bytes = prefixlen / 8;
	bits_left = prefixlen % 8;
	/* One bit left to check means ignore 7 lowest bits. */
	mask = ~( (1 << (8 - bits_left)) -1);

	for (i = 0; i < booth_conf->node_count; i++) {
		node = booth_conf->node + i;
		if (family != node->family)
			continue;
		n_a = node_to_addr_pointer(node);

		if (memcmp(ipaddr, n_a, node->addrlen) == 0) {
found:
			*me = node;
			return 1;
		}

		if (!fuzzy_allowed)
			continue;


//		assert(bytes <= node->addrlen);
//#include <stdio.h>
//		printf("node->addr %s, fam %d, prefix %d; %llx vs %llx, bytes %d\n", node->addr, node->family, prefixlen, *((long long*)&node->in6), *((long long*)ipaddr), bytes);
		/* Check prefix, whole bytes */
		if (memcmp(ipaddr, n_a, bytes) != 0)
			continue;
//printf("bits %d\n", bits_left);
		if (!bits_left)
			goto found;

		node_bits = n_a[bytes];
		ip_bits = ipaddr[bytes];
//printf("nodebits %x ip %x mask %x\n", node_bits, ip_bits, mask);
		if (((node_bits ^ ip_bits) & mask) == 0)
			goto found;
	}

	return 0;
}


int _find_myself(int family, struct booth_site **mep, int fuzzy_allowed);
int _find_myself(int family, struct booth_site **mep, int fuzzy_allowed)
{
	int fd;
	struct sockaddr_nl nladdr;
	struct booth_site *me;
	unsigned char ipaddr[BOOTH_IPADDR_LEN];
	static char rcvbuf[NETLINK_BUFSIZE];
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;


	if (local)
		goto found;


	me = NULL;
	if (mep)
		*mep = NULL;
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		log_error("failed to create netlink socket");
		return 0;
	}

	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETADDR;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 1;
	req.g.rtgen_family = family;

	if (sendto(fd, (void *)&req, sizeof(req), 0,
				(struct sockaddr*)&nladdr, sizeof(nladdr)) < 0)  {
		close(fd);
		log_error("failed to send data to netlink socket");
		return 0;
	}

	while (1) {
		int status;
		struct nlmsghdr *h;
		struct iovec iov = { rcvbuf, sizeof(rcvbuf) };
		struct msghdr msg = {
			(void *)&nladdr, sizeof(nladdr),
			&iov,   1,
			NULL,   0,
			0
		};

		status = recvmsg(fd, &msg, 0);
		if (!status) {
			close(fd);
			log_error("failed to recvmsg from netlink socket");
			return 0;
		}

		h = (struct nlmsghdr *)rcvbuf;
		if (h->nlmsg_type == NLMSG_DONE)
			break;

		if (h->nlmsg_type == NLMSG_ERROR) {
			close(fd);
			log_error("netlink socket recvmsg error");
			return 0;
		}

		while (NLMSG_OK(h, status)) {
			if (h->nlmsg_type == RTM_NEWADDR) {
				struct ifaddrmsg *ifa = NLMSG_DATA(h);
				struct rtattr *tb[IFA_MAX+1];
				int len = h->nlmsg_len 
					- NLMSG_LENGTH(sizeof(*ifa));

				memset(tb, 0, sizeof(tb));
				parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), len);
				memset(ipaddr, 0, BOOTH_IPADDR_LEN);
				memcpy(ipaddr, RTA_DATA(tb[IFA_ADDRESS]),
						BOOTH_IPADDR_LEN);

				if (find_address(ipaddr,
							ifa->ifa_family, ifa->ifa_prefixlen,
							fuzzy_allowed, &me))
					goto out;
			}
			h = NLMSG_NEXT(h, status);
		}
	}

out:
	close(fd);

	if (!me)
		return 0;

	me->local = 1;
	local = me;
found:
	if (mep)
		*mep = local;
	return 1;
}

int find_myself(struct booth_site **mep, int fuzzy_allowed)
{
	return _find_myself(AF_INET6, mep, fuzzy_allowed) ||
		_find_myself(AF_INET, mep, fuzzy_allowed);
}


/** Checks the header fields for validity.
 * cf. init_header().
 * For @len_incl_data < 0 the length is not checked.
 * Return <0 if error, else bytes read. */
int check_boothc_header(struct boothc_header *h, int len_incl_data)
{
	int l;

	if (h->magic != htonl(BOOTHC_MAGIC)) {
		log_error("magic error %x", ntohl(h->magic));
		return -EINVAL;
	}
	if (h->version != htonl(BOOTHC_VERSION)) {
		log_error("version error %x", ntohl(h->version));
		return -EINVAL;
	}


	l = ntohl(h->length);
	if (l < sizeof(*h)) {
		log_error("length %d out of range", l);
		return -EINVAL;
	}


	if (len_incl_data < 0)
		return 0;

	if (l != len_incl_data) {
		log_error("length error - got %d, wanted %d",
				l, len_incl_data);
		return -EINVAL;
	}

	return len_incl_data;
}

static void process_dead(int ci)
{
	struct tcp_conn *conn, *safe;

	list_for_each_entry_safe(conn, safe, &tcp, list) {
		if (conn->s == client[ci].fd) {
			list_del(&conn->list);
			free(conn);
			break;
		}
	}
	close(client[ci].fd);
	client[ci].workfn = NULL;
	client[ci].fd = -1;
	pollfd[ci].fd = -1;
}

static void process_tcp_listener(int ci)
{
	int fd, i, one = 1;
	socklen_t addrlen = sizeof(struct sockaddr);
	struct sockaddr addr;
	struct tcp_conn *conn;

	fd = accept(client[ci].fd, &addr, &addrlen);
	if (fd < 0) {
		log_error("process_tcp_listener: accept error %d %d",
			  fd, errno);
		return;
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));

	conn = malloc(sizeof(struct tcp_conn));
	if (!conn) {
		log_error("failed to alloc mem");
		return;
	}
	memset(conn, 0, sizeof(struct tcp_conn));
	conn->s = fd;
	memcpy(&conn->to, &addr, sizeof(struct sockaddr));
	list_add_tail(&conn->list, &tcp);

	i = client_add(fd, process_connection, process_dead);

	log_debug("client connection %d fd %d", i, fd);
}

static int setup_tcp_listener(void)
{
	int s, rv;

	s = socket(local->family, SOCK_STREAM, 0);
	if (s == -1) {
		log_error("failed to create tcp socket %s", strerror(errno));
		return s;
	}

	rv = bind(s, &local->sa6, local->saddrlen);
	if (rv == -1) {
		log_error("failed to bind socket %s", strerror(errno));
		return rv;
	}

	rv = listen(s, 5);
	if (rv == -1) {
		log_error("failed to listen on socket %s", strerror(errno));
		return rv;
	}

	return s;
}

static int booth_tcp_init(void * unused __attribute__((unused)))
{
	int rv;

	if (get_local_id() < 0)
		return -1;

	rv = setup_tcp_listener();
	if (rv < 0)
		return rv;

	client_add(rv, process_tcp_listener, NULL);

	return 0;
}

static int connect_nonb(int sockfd, const struct sockaddr *saptr,
			socklen_t salen, int sec)
{
	int		flags, n, error;
	socklen_t	len;
	fd_set		rset, wset;
	struct timeval	tval;

	flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	error = 0;
	if ( (n = connect(sockfd, saptr, salen)) < 0)
		if (errno != EINPROGRESS)
			return -1;

	if (n == 0)
		goto done;	/* connect completed immediately */

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tval.tv_sec = sec;
	tval.tv_usec = 0;

	if ((n = select(sockfd + 1, &rset, &wset, NULL,
	    sec ? &tval : NULL)) == 0) {
		/* leave outside function to close */
		/* timeout */
		/* close(sockfd); */	
		errno = ETIMEDOUT;
		return -1;
	}

	if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
		len = sizeof(error);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return -1;	/* Solaris pending error */
	} else {
		log_error("select error: sockfd not set");
		return -1;
	}

done:
	fcntl(sockfd, F_SETFL, flags);	/* restore file status flags */

	if (error) {
		/* leave outside function to close */
		/* close(sockfd); */	
		errno = error;
		return -1;
	}

	return 0;
}

int booth_tcp_open(struct booth_site *to)
{
	int s, rv;

	if (to->tcp_fd >= STDERR_FILENO)
		goto found;

	s = socket(to->family, SOCK_STREAM, 0);
	if (s == -1) {
		log_error("cannot create socket of family %d", to->family);
		return -1;
	}


	rv = connect_nonb(s, (struct sockaddr *)&to->sa6, to->saddrlen, 10);
	if (rv == -1) {
		if( errno == ETIMEDOUT)
			log_error("connection to %s timeout", to->addr_string);
		else 
			log_error("connection to %s error %s", to->addr_string,
					strerror(errno));
		goto error;
	}

	to->tcp_fd = s;

found:
	return 1;

error:
	if (s >= 0)
		close(s);
	return -1;
}

int booth_tcp_send(struct booth_site *to, void *buf, int len)
{
	return do_write(to->tcp_fd, buf, len);
}

static int booth_tcp_recv(struct booth_site *from, void *buf, int len)
{
	int got;
	/* Needs timeouts! */
	got = do_read(from->tcp_fd, buf, len);
	if (got < 0)
		return got;
	if (got != len)
		return -EINVAL;
	return len;
}

static int booth_tcp_close(struct booth_site *to)
{
	if (to) {
		if (to->tcp_fd > STDERR_FILENO)
			close(to->tcp_fd);
		to->tcp_fd = -1;
	}
	return 0;
}

static int booth_tcp_exit(void)
{
	return 0;
}

int setup_udp_server(int try_only)
{
	int rv;
	unsigned int recvbuf_size;

	udp.s = socket(local->family, SOCK_DGRAM, 0);
	if (udp.s == -1) {
		log_error("failed to create udp socket %s", strerror(errno));
		return -1;
	}

	rv = fcntl(udp.s, F_SETFL, O_NONBLOCK);
	if (rv == -1) {
		log_error("failed to set non-blocking operation "
			  "on udp socket: %s", strerror(errno));
		close(udp.s);
		return -1;
	}

	rv = bind(udp.s, (struct sockaddr *)&local->sa6, local->saddrlen);
	if (try_only) {
		rv = (rv == -1) ? errno : 0;
		close(udp.s);
		return rv;
	}

	if (rv == -1) {
		log_error("failed to bind socket %s", strerror(errno));
		close(udp.s);
		return -1;
	}

	recvbuf_size = SOCKET_BUFFER_SIZE;
	rv = setsockopt(udp.s, SOL_SOCKET, SO_RCVBUF, 
			&recvbuf_size, sizeof(recvbuf_size));
	if (rv == -1) {
		log_error("failed to set recvbuf size");
		close(udp.s);
		return -1;
	}

	return udp.s;
}

static void process_recv(int ci)
{
	struct msghdr msg_recv;
	struct sockaddr_storage system_from;
	int received;
	unsigned char *msg_offset;

	/* TODO: allocate on stack? */
	msg_recv.msg_name = &system_from;
	msg_recv.msg_namelen = sizeof (struct sockaddr_storage);
	msg_recv.msg_iov = &udp.iov_recv;
	msg_recv.msg_iovlen = 1;
	msg_recv.msg_control = 0;
	msg_recv.msg_controllen = 0;
	msg_recv.msg_flags = 0;

	received = recvmsg(client[ci].fd, &msg_recv,
			   MSG_NOSIGNAL | MSG_DONTWAIT);
	if (received == -1)
		return;

	msg_offset = udp.iov_recv.iov_base;

	deliver_fn(msg_offset, received);
}

static int booth_udp_init(void *f)
{
	memset(&udp, 0, sizeof(struct udp_context));
	udp.iov_recv.iov_base = udp.iov_buffer;
	udp.iov_recv.iov_len = FRAME_SIZE_MAX;   

	udp.s = setup_udp_server(0);
	if (udp.s == -1)
		return -1;

	deliver_fn = f;

	client_add(udp.s, process_recv, NULL);

	return 0;
}

static int booth_udp_send(struct booth_site *to, void *buf, int len)
{
	struct msghdr msg;
	struct iovec iovec;
	unsigned int iov_len;
	int rv;

	iovec.iov_base = (void *)buf;
	iovec.iov_len = len;
	iov_len = 1;

	msg.msg_name = &to->sa6;
	msg.msg_namelen = to->addrlen;
	msg.msg_iov = (void *)&iovec;
	msg.msg_iovlen = iov_len;
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	rv = sendmsg(udp.s, &msg, MSG_NOSIGNAL);
	if (rv < 0)
		return rv;

	return 0;
}

static int booth_udp_broadcast(void *buf, int len)
{
	int i;

	if (!booth_conf || !booth_conf->node_count)
		return -1;

	for (i = 0; i < booth_conf->node_count; i++)
		booth_udp_send(booth_conf->node+i, buf, len);
	
	return 0;
}

static int booth_udp_exit(void)
{
	return 0;
}

/* SCTP transport layer has not been developed yet */
static int booth_sctp_init(void *f __attribute__((unused)))
{
	return 0;
}

static int booth_sctp_send(struct booth_site * to __attribute__((unused)),
			   void *buf __attribute__((unused)),
			   int len __attribute__((unused)))
{
	return 0;
}

static int booth_sctp_broadcast(void *buf __attribute__((unused)),
				int len __attribute__((unused)))
{
	return 0;
}

static int return_0_booth_site(struct booth_site *v __attribute((unused)))
{
	return 0;
}

static int return_0(void)
{
	return 0;
}
const struct booth_transport booth_transport[TRANSPORT_ENTRIES] = {
	[TCP] = {
		.name = "TCP",
		.init = booth_tcp_init,
		.open = booth_tcp_open,
		.send = booth_tcp_send,
		.recv = booth_tcp_recv,
		.close = booth_tcp_close,
		.exit = booth_tcp_exit
	},
	[UDP] = {
		.name = "UDP",
		.init = booth_udp_init,
		.open = return_0_booth_site,
		.send = booth_udp_send,
		.broadcast = booth_udp_broadcast,
		.exit = booth_udp_exit
	},
	[SCTP] = {
		.name = "SCTP",
		.init = booth_sctp_init,
		.open = return_0_booth_site,
		.send = booth_sctp_send,
		.broadcast = booth_sctp_broadcast,
		.exit = return_0,
	}
};

const struct booth_transport *local_transport = booth_transport+TCP;



int send_header_only(int fd, struct boothc_header *hdr)
{
	int rv;

	rv = do_write(fd, hdr, sizeof(*hdr));

	return rv;
}


int send_ticket_msg(int fd, struct boothc_ticket_msg *msg)
{
	int rv;

	rv = do_write(fd, msg, sizeof(*msg));

	return rv;
}


int send_header_plus(int fd, struct boothc_header *hdr, void *data, int len)
{
	int rv;
	int l;

	if (data == hdr->data) {
		l = sizeof(*hdr) + len;
		assert(l == ntohl(hdr->length));

		/* One struct */
		rv = do_write(fd, hdr, l);
	} else {
		/* Header and data in two locations */
		rv = send_header_only(fd, hdr);

		if (rv >= 0 && len)
			rv = do_write(fd, data, len);
	}

	return rv;
}
