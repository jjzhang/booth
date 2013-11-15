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
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <pacemaker/crm/services.h>
#include <clplumbing/setproctitle.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <error.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include "log.h"
#include "booth.h"
#include "config.h"
#include "transport.h"
#include "timer.h"
#include "pacemaker.h"
#include "ticket.h"

#define RELEASE_VERSION		"1.0"

#define CLIENT_NALLOC		32

int log_logfile_priority = LOG_INFO;
int log_syslog_priority = LOG_ERR;
int log_stderr_priority = LOG_ERR;
int daemonize = 0;

static int client_maxi;
static int client_size = 0;
struct client *client = NULL;
struct pollfd *pollfd = NULL;

typedef enum 
{
	BOOTHD_STARTED=0,
	BOOTHD_STARTING
} BOOTH_DAEMON_STATE;

int poll_timeout = -1;

typedef enum {
	OP_LIST = 1,
	OP_GRANT,
	OP_REVOKE,
} operation_t;

struct command_line {
	int type;		/* ACT_ */
	int op;			/* OP_ */
	char configfile[BOOTH_PATH_LEN];
	char lockfile[BOOTH_PATH_LEN];

	struct boothc_site_ticket_msg msg;
};

static struct command_line cl;

int do_read(int fd, void *buf, size_t count)
{
	int rv, off = 0;

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0)
			return -1;
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv == -1)
			return -1;
		off += rv;
	}
	return 0;
}

int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	/* If we cannot write _any_ data, we'd be in an (potential) loop. */
	if (rv <= 0) {
		log_error("write failed: %s (%d)", strerror(errno), errno);
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}


static int do_local_connect_and_write(void *data, int len, struct booth_node **ret)
{
	struct booth_node *node;
	int rv;


	if (ret)
		*ret = NULL;

	/* Use locally reachable address, ie. in same cluster. */
	if (!find_myself(&node, 1)) {
		log_error("Cannot find local cluster.");
		return ENOENT;
	}

	if (ret)
		*ret = node;


	/* Always use TCP within cluster. */
	rv = booth_tcp_open(node);
	if (rv < 0)
		goto out;

	rv = booth_tcp_send(node, data, len);

out:
	return rv;
}


static void init_header(struct boothc_header *h, int cmd,
			int result, int data_len)
{
	memset(h, 0, sizeof(struct boothc_header));

	h->magic = BOOTHC_MAGIC;
	h->version = BOOTHC_VERSION;
	h->len = data_len;
	h->cmd = cmd;
	h->result = result;
}

static void client_alloc(void)
{
	int i;

	if (!client) {
		client = malloc(CLIENT_NALLOC * sizeof(struct client));
		pollfd = malloc(CLIENT_NALLOC * sizeof(struct pollfd));
	} else {
		client = realloc(client, (client_size + CLIENT_NALLOC) *
					sizeof(struct client));
		pollfd = realloc(pollfd, (client_size + CLIENT_NALLOC) *
					sizeof(struct pollfd));
		if (!pollfd)
			log_error("can't alloc for pollfd");
	}
	if (!client || !pollfd)
		log_error("can't alloc for client array");

	for (i = client_size; i < client_size + CLIENT_NALLOC; i++) {
		client[i].workfn = NULL;
		client[i].deadfn = NULL;
		client[i].fd = -1;
		pollfd[i].fd = -1;
		pollfd[i].revents = 0;
	}
	client_size += CLIENT_NALLOC;
}

static void client_dead(int ci)
{
	close(client[ci].fd);
	client[ci].workfn = NULL;
	client[ci].fd = -1;
	pollfd[ci].fd = -1;
}

int client_add(int fd, void (*workfn)(int ci), void (*deadfn)(int ci))
{
	int i;

	if (!client)
		client_alloc();
again:
	for (i = 0; i < client_size; i++) {
		if (client[i].fd == -1) {
			client[i].workfn = workfn;
			if (deadfn)
				client[i].deadfn = deadfn;
			else
				client[i].deadfn = client_dead;
			client[i].fd = fd;
			pollfd[i].fd = fd;
			pollfd[i].events = POLLIN;
			if (i > client_maxi)
				client_maxi = i;
			return i;
		}
	}

	client_alloc();
	goto again;
}


void process_connection(int ci)
{
	struct boothc_site_ticket_msg msg;
	char *data = NULL;
	int ticket_owner;
	int is_local, rv;
	void (*deadfn) (int ci);

	rv = do_read(client[ci].fd, &msg.header, sizeof(msg.header));

	if (rv < 0) {
		if (errno == ECONNRESET)
			log_debug("client %d connection reset for fd %d",
				  ci, client[ci].fd);

		deadfn = client[ci].deadfn;
		if(deadfn) {
			deadfn(ci);
		}
		return;
	}
	if (msg.header.magic != BOOTHC_MAGIC) {
		log_error("connection %d magic error %x", ci, msg.header.magic);
		return;
	}
	if (msg.header.version != BOOTHC_VERSION) {
		log_error("connection %d version error %x", ci, msg.header.version);
		return;
	}

	if (msg.header.len) {
		if (msg.header.len != sizeof(msg) - sizeof(msg.header)) {
			log_error("got wrong length %u", msg.header.len);
			return;
		}
		rv = do_read(client[ci].fd, msg.header.data, msg.header.len);
		if (rv < 0) {
			log_error("connection %d read data error %d", ci, rv);
			goto out;
		}
	}

	switch (msg.header.cmd) {
	case BOOTHC_CMD_LIST:
		assert(!data);
		msg.header.result = list_ticket(&data, &msg.header.len);
		break;

	case BOOTHC_CMD_GRANT:
		msg.header.len = 0;

		if (!check_ticket(msg.ticket)) {
			msg.header.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}

		if (get_ticket_info(msg.ticket, &ticket_owner, NULL) == 0) {
			if (ticket_owner > -1) {
				log_error("client want to get an granted "
					  "ticket %s", msg.ticket);
				msg.header.result = BOOTHC_RLT_OVERGRANT;
				goto reply;
			}
		} else {
			log_error("can not get ticket %s's info", msg.ticket);
			msg.header.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}

		if (!check_site(msg.site, &is_local)) {
			msg.header.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}
		if (is_local)
			msg.header.result = grant_ticket(msg.ticket);
		else
			msg.header.result = BOOTHC_RLT_REMOTE_OP;
		break;

	case BOOTHC_CMD_REVOKE:
		msg.header.len = 0;
		if (!check_ticket(msg.ticket)) {
			msg.header.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}
		if (!check_site(msg.site, &is_local)) {
			msg.header.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}
		if (is_local)
			msg.header.result = revoke_ticket(msg.ticket);
		else
			msg.header.result = BOOTHC_RLT_REMOTE_OP;
		break;

	case BOOTHC_CMD_CATCHUP:
		msg.header.result = catchup_ticket(&data, msg.header.len);	
		break;

	default:
		log_error("connection %d cmd %x unknown", ci, msg.header.cmd);
		break;
	}

reply:
	rv = do_write(client[ci].fd, &msg.header, sizeof(msg.header));
	if (rv < 0)
		log_error("connection %d write error %d", ci, rv);
	if (msg.header.len) {
		rv = do_write(client[ci].fd, data, msg.header.len);
		if (rv < 0)
			log_error("connection %d write error %d", ci, rv);
	}
out:
	free(data);	
}

static void process_listener(int ci)
{
	int fd, i;

	fd = accept(client[ci].fd, NULL, NULL);
	if (fd < 0) {
		log_error("process_listener: accept error for fd %d: %s (%d)",
			  client[ci].fd, strerror(errno), errno);
		if (client[ci].deadfn)
			client[ci].deadfn(ci);
		return;
	}

	i = client_add(fd, process_connection, NULL);

	log_debug("add client connection %d fd %d", i, fd);
}

static int setup_config(int type)
{
	int rv;

	rv = read_config(cl.configfile);
	if (rv < 0)
		goto out;

	/* Set "local" pointer, ignoring errors. */
	find_myself(NULL, 0);


	rv = check_config(type);
	if (rv < 0)
		goto out;


	/* Per default the PID file name is derived from the
	 * configuration name. */
	if (!cl.lockfile[0]) {
		snprintf(cl.lockfile, sizeof(cl.lockfile)-1,
				"%s/%s.pid", BOOTH_RUN_DIR, booth_conf->name);
	}

out:
	return rv;
}

static int setup_transport(void)
{
	int rv;

	rv = transport()->init(ticket_recv);
	if (rv < 0) {
		log_error("failed to init booth_transport %s", transport()->name);
		goto out;
	}

	rv = booth_transport[TCP].init(NULL);
	if (rv < 0) {
		log_error("failed to init booth_transport[TCP]");
		goto out;
	}

out:
	return rv;
}

static int setup_timer(void)
{
	return timerlist_init();
}

static int write_daemon_state(int fd, int state)
{
	char buffer[1024];
	int rv, size;

	size = sizeof(buffer) - 1;
	rv = snprintf(buffer, size,
			"booth_pid=%d "
			"booth_state=%s "
			"booth_type=%s "
			"booth_cfg_name='%s' "
			"booth_addr_string='%s' "
			"booth_port=%d\n",
		getpid(), 
		( state == BOOTHD_STARTED  ? "started"  : 
		  state == BOOTHD_STARTING ? "starting" : 
		  "invalid"), 
		type_to_string(local->type),
		booth_conf->name,
		local->addr_string,
		booth_conf->port);

	if (rv < 0 || rv == size) {
		log_error("Buffer filled up in write_daemon_state().");
		return -1;
	}
	size = rv;


	rv = lseek(fd, 0, SEEK_SET);
	if (rv < 0) {
		log_error("lseek set fd(%d) offset to 0 error, return(%d), message(%s)",
			fd, rv, strerror(errno));
		rv = -1;
		return rv;
	} 


	rv = write(fd, buffer, size);

	if (rv != size) {
		log_error("write to fd(%d, %d) returned %d, errno %d, message(%s)",
                      fd, size,
		      rv, errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int loop(int fd)
{
	void (*workfn) (int ci);
	void (*deadfn) (int ci);
	int rv, i;
	
	rv = setup_timer();
	if (rv < 0)
		goto fail;

	rv = setup_transport();
	if (rv < 0)
		goto fail;

	rv = setup_ticket();
	if (rv < 0)
		goto fail;

	client_add(rv, process_listener, NULL);

	rv = write_daemon_state(fd, BOOTHD_STARTED);
	if (rv != 0) {
		log_error("write daemon state %d to lockfile error %s: %s",
                      BOOTHD_STARTED, cl.lockfile, strerror(errno));
		goto fail;
	}

	if (cl.type == ARBITRATOR)
		log_info("BOOTH arbitrator daemon started");
	else if (cl.type == SITE)
		log_info("BOOTH cluster site daemon started");

        while (1) {
                rv = poll(pollfd, client_maxi + 1, poll_timeout);
                if (rv == -1 && errno == EINTR)
                        continue;
                if (rv < 0) {
                        log_error("poll failed: %s (%d)", strerror(errno), errno);
                        goto fail;
                }

                for (i = 0; i <= client_maxi; i++) {
                        if (client[i].fd < 0)
                                continue;
                        if (pollfd[i].revents & POLLIN) {
                                workfn = client[i].workfn;
                                if (workfn)
                                        workfn(i);
                        }
                        if (pollfd[i].revents &
			    (POLLERR | POLLHUP | POLLNVAL)) {
                                deadfn = client[i].deadfn;
                                if (deadfn)
                                        deadfn(i);
                        }
                }

		process_timerlist();
	}

	return 0;

fail:
	return -1;
}


static int query_get_string_answer(cmd_request_t cmd)
{
	struct booth_node *node;
	struct boothc_header h, *rh;
	char *reply = NULL, *data;
	int data_len;
	int rv;

	init_header(&h, cmd, 0, 0);

	rv = do_local_connect_and_write(&h, sizeof(h), &node);
	if (rv < 0)
		goto out;

	reply = malloc(sizeof(struct boothc_header));
	if (!reply) {
		rv = -ENOMEM;
		goto out_close;
	}

	rv = local_transport->recv(node, reply, sizeof(struct boothc_header));
	if (rv < 0)
		goto out_free;

	rh = (struct boothc_header *)reply;
	data_len = rh->len;

	reply = realloc(reply, sizeof(struct boothc_header) + data_len);
	if (!reply) {
		rv = -ENOMEM;
		goto out_free;
	}
	data = reply + sizeof(struct boothc_header);
	rv = local_transport->recv(node, data, data_len);
	if (rv < 0)
		goto out_free;

	do_write(STDOUT_FILENO, data, data_len);
	rv = 0;

out_free:
	free(reply);
out_close:
	local_transport->close(node);
out:
	return rv;
}

static int do_command(cmd_request_t cmd)
{
	struct booth_node *node, *to;
	struct boothc_header reply;
	int rv;

	node = NULL;
	to = NULL;

	init_header(&cl.msg.header, cmd, 0,
			sizeof(cl.msg) - sizeof(cl.msg.header));

	rv = do_local_connect_and_write(&cl.msg, sizeof(cl.msg), &node);
        if (rv < 0)
                goto out_close;

	rv = local_transport->recv(node, &reply, sizeof(reply));
	if (rv < 0)
		goto out_close;

	if (reply.result == BOOTHC_RLT_INVALID_ARG) {
		log_info("invalid argument!");
		rv = -1;
		goto out_close;
	}
	
	if (reply.result == BOOTHC_RLT_OVERGRANT) {
		log_info("You're granting a granted ticket "
			 "If you wanted to migrate a ticket,"
			 "use revoke first, then use grant");
		rv = -1;
		goto out_close;
	}
	
	if (reply.result == BOOTHC_RLT_REMOTE_OP) {

		if (!find_site_in_config(cl.msg.site, &to)) {
			log_error("Redirected to unknown site %s.", cl.msg.site);
			rv = -1;
			goto out_close;
		}

		rv = booth_transport[TCP].open(to);
		if (rv < 0) {
			goto out_close;
		}
		rv = booth_transport[TCP].send(to, &cl.msg, sizeof(cl.msg));
		if (rv < 0) {
			booth_transport[TCP].close(to);
			goto out_close;
		}
		rv = booth_transport[TCP].recv(to, &reply,
					       sizeof(struct boothc_header));
		if (rv < 0) {	
			booth_transport[TCP].close(to);
			goto out_close;
		}
		booth_transport[TCP].close(to);
	}
 
	if (reply.result == BOOTHC_RLT_ASYNC) {
		if (cmd == BOOTHC_CMD_GRANT)
			log_info("grant command sent, result will be returned "
				 "asynchronously, you can get the result from "
				 "the log files");
		else if (cmd == BOOTHC_CMD_REVOKE)
			log_info("revoke command sent, result will be returned "
				 "asynchronously, you can get the result from "
				 "the log files.");
		else
			log_error("internal error reading reply result!");
		rv = 0;
	} else if (reply.result == BOOTHC_RLT_SYNC_SUCC) {
		if (cmd == BOOTHC_CMD_GRANT)
			log_info("grant succeeded!");
		else if (cmd == BOOTHC_CMD_REVOKE)
			log_info("revoke succeeded!");
		rv = 0;
	} else if (reply.result == BOOTHC_RLT_SYNC_FAIL) {
		if (cmd == BOOTHC_CMD_GRANT)
			log_info("grant failed!");
		else if (cmd == BOOTHC_CMD_REVOKE)
			log_info("revoke failed!");
		rv = -1;
	} else {
		log_error("internal error!");
		rv = -1;
	}

out_close:
	if (node)
		local_transport->close(node);
	if (to)
		booth_transport[TCP].close(to);
	return rv;
}

static int do_grant(void)
{
	return do_command(BOOTHC_CMD_GRANT);
}

static int do_revoke(void)
{
	return do_command(BOOTHC_CMD_REVOKE);
}



static int _lockfile(int mode, int *fdp, pid_t *locked_by)
{
	struct flock lock;
	int fd, rv;


	/* After reboot the directory may not yet exist.
	 * Try to create it, but ignore errors. */
	if (strncmp(cl.lockfile, BOOTH_RUN_DIR,
				strlen(BOOTH_RUN_DIR)) == 0)
		mkdir(BOOTH_RUN_DIR, 0775);


	if (locked_by)
		*locked_by = 0;

	*fdp = -1;
	fd = open(cl.lockfile, mode, 0664);
	if (fd < 0)
		return errno;

	*fdp = fd;

	lock.l_type = F_WRLCK;
	lock.l_start = 0;
	lock.l_whence = SEEK_SET;
	lock.l_len = 0;
	lock.l_pid = 0;


	if (fcntl(fd, F_SETLK, &lock) == 0)
		return 0;

	rv = errno;

	if (locked_by)
		if (fcntl(fd, F_GETLK, &lock) == 0)
			*locked_by = lock.l_pid;

	return rv;
}


static int lockfile(void) {
	int rv, fd;

	fd = -1;
	rv = _lockfile(O_CREAT | O_WRONLY, &fd, NULL);

	if (fd == -1) {
		log_error("lockfile %s open error %d: %s",
				cl.lockfile, rv, strerror(rv));
		return -1;
	}       

	if (rv < 0) {
		log_error("lockfile %s setlk error %d: %s",
				cl.lockfile, rv, strerror(rv));
		goto fail;
	}

	rv = ftruncate(fd, 0);
	if (rv < 0) {
		log_error("lockfile %s truncate error %d: %s",
				cl.lockfile, errno, strerror(errno));
		goto fail;
	}

	rv = write_daemon_state(fd, BOOTHD_STARTING);
	if (rv != 0) {
		log_error("write daemon state %d to lockfile error %s: %s",
				BOOTHD_STARTING, cl.lockfile, strerror(errno));
		goto fail;
	}

	return fd;

fail:
	close(fd);
	return -1;
}

static void unlink_lockfile(int fd)
{
	unlink(cl.lockfile);
	close(fd);
}

static void print_usage(void)
{
	printf("Usage:\n");
	printf("booth <type> <operation> [options]\n");
	printf("\n");
	printf("Types:\n");
	printf("  arbitrator:   daemon running on arbitrator\n");
	printf("  site:	        daemon running on cluster site\n");
	printf("  client:       command running from client\n");
	printf("\n");
	printf("Operations:\n");
	printf("Please note that operations are valid iff type is client!\n");
	printf("  list:	        List all the tickets\n");
	printf("  grant:        Grant ticket T(-t T) to site S(-s S)\n");
	printf("  revoke:       Revoke ticket T(-t T) from site S(-s S)\n");
	printf("\n");
	printf("Options:\n");
	printf("  -c FILE       Specify config file [default " BOOTH_DEFAULT_CONF "]\n");
	printf("  -l LOCKFILE   Specify lock file path\n");
	printf("  -D            Enable debugging to stderr and don't fork\n");
	printf("  -t            ticket name\n");
	printf("  -S            report local daemon status (for site and arbitrator)\n");
	printf("                RA script compliant return codes.\n");
	printf("  -s            site name\n");
	printf("  -h            Print this help, then exit\n");
}

#define OPTION_STRING		"c:Dl:t:s:hS"

static char *logging_entity = NULL;

void safe_copy(char *dest, char *value, size_t buflen, const char *description) {
	int content_len = buflen - 1;

	if (strlen(value) >= content_len) {
		fprintf(stderr, "'%s' exceeds maximum %s length of %d\n",
			value, description, content_len);
		exit(EXIT_FAILURE);
	}
	strncpy(dest, value, content_len);
	dest[content_len] = 0;
}

static int host_convert(char *hostname, char *ip_str, size_t ip_size)
{
	struct addrinfo *result = NULL, hints = {0};
	int re = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = BOOTH_PROTO_FAMILY;
	hints.ai_socktype = SOCK_DGRAM;

	re = getaddrinfo(hostname, NULL, &hints, &result);

	if (re == 0) {
		struct in_addr addr = ((struct sockaddr_in *)result->ai_addr)->sin_addr;
		const char *re_ntop = inet_ntop(BOOTH_PROTO_FAMILY, &addr, ip_str, ip_size);
		if (re_ntop == NULL) {
			re = -1;
		}
	}

	freeaddrinfo(result);
	return re;
}

static int read_arguments(int argc, char **argv)
{
	int optchar;
	char *arg1 = argv[1];
	char *op = NULL;
	char site_arg[INET_ADDRSTRLEN] = {0};

	if (argc < 2 || !strcmp(arg1, "help") || !strcmp(arg1, "--help") ||
		!strcmp(arg1, "-h")) {
		print_usage();
		exit(EXIT_SUCCESS);
	}

	if (!strcmp(arg1, "version") || !strcmp(arg1, "--version") ||
		!strcmp(arg1, "-V")) {
		printf("%s %s (built %s %s)\n",
			argv[0], RELEASE_VERSION, __DATE__, __TIME__);
		exit(EXIT_SUCCESS);
	}

	if (strcmp(arg1, "arbitrator") == 0 ||
			strcmp(arg1, "site") == 0 ||
			strcmp(arg1, "start") == 0 ||
			strcmp(arg1, "daemon") == 0) {
		cl.type = DAEMON;
		optind = 2;
	} else if (strcmp(arg1, "status") == 0) {
		cl.type = STATUS;
		optind = 2;
	} else if (strcmp(arg1, "client") == 0) {
		cl.type = CLIENT;
		if (argc < 3) {
			print_usage();
			exit(EXIT_FAILURE);
		}
		op = argv[2];
		optind = 3;
	} else {
		cl.type = CLIENT;
		op = argv[1];
		optind = 2;
	}

	switch (cl.type) {
	case ARBITRATOR:
		break;

	case SITE:
		break;

	case CLIENT:
		if (!strcmp(op, "list"))
			cl.op = OP_LIST;
		else if (!strcmp(op, "grant"))
			cl.op = OP_GRANT;
		else if (!strcmp(op, "revoke"))
			cl.op = OP_REVOKE;
		else {
			fprintf(stderr, "client operation \"%s\" is unknown\n",
				op);
			exit(EXIT_FAILURE);
		}
		break;
	}

	while (optind < argc) {
		optchar = getopt(argc, argv, OPTION_STRING);

		switch (optchar) {
		case 'c':
			safe_copy(cl.configfile, optarg, sizeof(cl.configfile), "config file");
			break;
		case 'D':
			daemonize = 1;
			debug_level = 1;
			log_logfile_priority = LOG_DEBUG;
			log_syslog_priority = LOG_DEBUG;
			break;

		case 'l':
			safe_copy(cl.lockfile, optarg, sizeof(cl.lockfile), "lock file");
			break;
		case 't':
			if (cl.op == OP_GRANT || cl.op == OP_REVOKE) {
				safe_copy(cl.msg.ticket, optarg, sizeof(cl.msg.ticket), "ticket name");
			} else {
				print_usage();
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			if (cl.op == OP_GRANT || cl.op == OP_REVOKE) {
				int re = host_convert(optarg, site_arg, INET_ADDRSTRLEN);
				if (re == 0) {
					safe_copy(cl.msg.site, site_arg, sizeof(cl.msg.ticket), "site name");
				} else {
					safe_copy(cl.msg.site, optarg, sizeof(cl.msg.ticket), "site name");
				}
			} else {
				print_usage();
				exit(EXIT_FAILURE);
			}
			break;

		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;

		case ':':
		case '?':
			fprintf(stderr, "Please use '-h' for usage.\n");
			exit(EXIT_FAILURE);
			break;
		
		default:
			fprintf(stderr, "unknown option: %s\n", argv[optind]);
			exit(EXIT_FAILURE);
			break;
		};
	}

	return 0;
}

static void set_scheduler(void)
{
	struct sched_param sched_param;
	struct rlimit rlimit;
	int rv;

	rlimit.rlim_cur = RLIM_INFINITY;
	rlimit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_MEMLOCK, &rlimit);
	rv = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (rv < 0) {
		log_error("mlockall failed");
	}

	rv = sched_get_priority_max(SCHED_RR);
	if (rv != -1) {
		sched_param.sched_priority = rv;
		rv = sched_setscheduler(0, SCHED_RR, &sched_param);
		if (rv == -1)
			log_error("could not set SCHED_RR priority %d: %s (%d)",
					sched_param.sched_priority,
					strerror(errno), errno);
	} else {
		log_error("could not get maximum scheduler priority err %d",
				errno);
	}
}

static void set_oom_adj(int val)
{
        FILE *fp;

        fp = fopen("/proc/self/oom_adj", "w");
        if (!fp)
                return;

        fprintf(fp, "%i", val);
        fclose(fp);
}

static int do_status(int type)
{
    pid_t pid;
    int rv, lock_fd, ret;
    const char *reason = NULL;
    char lockfile_data[1024], *cp;


    ret = PCMK_OCF_NOT_RUNNING;
    /* TODO: query all, and return quit only if it's _cleanly_ not
     * running, ie. _neither_ of port/lockfile/process is available?
     *
     * Currently a single failure says "not running", even if "only" the
     * lockfile has been removed. */

    rv = setup_config(type);
    if (rv) {
	reason = "Error reading configuration.";
	ret = PCMK_LSB_UNKNOWN_ERROR;
	goto quit;
    }


    if (!local) {
	reason = "No Service IP active here.";
	goto quit;
    }


    rv = _lockfile(O_RDWR, &lock_fd, &pid);
    if (rv == 0) {
	reason = "PID file not locked.";
	goto quit;
    }
    if (lock_fd == -1) {
	reason = "No PID file.";
	goto quit;
    }

    if (pid) {
	fprintf(stdout, "booth_lockpid=%d ", pid);
	fflush(stdout);
    }


    rv = read(lock_fd, lockfile_data, sizeof(lockfile_data) - 1);
    if (rv < 4) {
	reason = "Cannot read lockfile data.";
	ret = PCMK_LSB_UNKNOWN_ERROR;
	goto quit;

    }
    lockfile_data[rv] = 0;

    if (lock_fd != -1)
	close(lock_fd);


    /* Make sure it's only a single line */
    cp = strchr(lockfile_data, '\r');
    if (cp)
	*cp = 0;
    cp = strchr(lockfile_data, '\n');
    if (cp)
	*cp = 0;



    rv = setup_udp_server(1);
    if (rv == 0) {
	reason = "UDP port not in use.";
	goto quit;
    }


    fprintf(stdout, "booth_lockfile='%s' %s\n",
		    cl.lockfile, lockfile_data);
    if (daemonize)
	fprintf(stderr, "Booth at %s port %d seems to be running.\n",
		local->addr_string, booth_conf->port);
    return 0;


quit:
    log_debug("not running: %s", reason);
    /* Ie. "DEBUG" */
    if (daemonize)
	fprintf(stderr, "not running: %s\n", reason);
    return ret;
}


static int do_server(int type)
{
	int lock_fd = -1;
	int rv = -1;
	static char log_ent[128] = DAEMON_NAME "-";

	rv = setup_config(type);
	if (rv < 0)
		goto out;


	if (!local) {
		log_error("Cannot find myself in the configuration.");
		exit(EXIT_FAILURE);
	}

	if (!daemonize) {
		if (daemon(0, 0) < 0) {
			perror("daemon error");
			exit(EXIT_FAILURE);
		}
	}

	/*
	   The lock cannot be obtained before the call to daemon(), otherwise
	   the lockfile would contain the pid of the parent, not the daemon.
	 */
	lock_fd = lockfile();
	if (lock_fd < 0)
		return lock_fd;

	if (local->type == ARBITRATOR)
		log_info("BOOTH arbitrator daemon is starting.");
	else if (local->type == SITE)
		log_info("BOOTH cluster site daemon is starting.");

	strcat(log_ent, type_to_string(local->type));
	logging_entity = log_ent;

	set_scheduler();
	set_oom_adj(-16);
	set_proc_title("%s %s for [%s]:%d",
			DAEMON_NAME,
			type_to_string(local->type),
			local->addr_string,
			booth_conf->port);

	rv = loop(lock_fd);

out:
	if (lock_fd >= 0)
		unlink_lockfile(lock_fd);

	return rv;
}

static int do_client(void)
{
	int rv = -1;

	rv = setup_config(CLIENT);
	if (rv < 0) {
		log_error("cannot read config");
		goto out;
	}

	switch (cl.op) {
	case OP_LIST:
		rv = query_get_string_answer(BOOTHC_CMD_LIST);
		break;

	case OP_GRANT:
		rv = do_grant();
		break;

	case OP_REVOKE:
		rv = do_revoke();
		break;
	}
	
out:
	return rv;
}

int main(int argc, char *argv[], char *envp[])
{
	int rv;

	init_set_proc_title(argc, argv, envp);
	memset(&cl, 0, sizeof(cl));
	strncpy(cl.configfile, BOOTH_DEFAULT_CONF,     BOOTH_PATH_LEN - 1);
	cl.lockfile[0] = 0;

	rv = read_arguments(argc, argv);
	if (rv < 0)
		goto out;


	if (cl.type == STATUS) {
		return do_status(cl.type);
	}


	if (cl.type == CLIENT) {
		cl_log_enable_stderr(TRUE);
		cl_log_set_facility(0);
	} else {
		cl_log_set_entity(logging_entity);
		cl_log_enable_stderr(debug_level ? TRUE : FALSE);
		cl_log_set_facility(HA_LOG_FACILITY);
	}
	cl_inherit_logging_environment(0);


	switch (cl.type) {
	case ARBITRATOR:
	case DAEMON:
	case SITE:
		rv = do_server(cl.type);
		break;

	case CLIENT:
		rv = do_client();
		break;
	}

out:
	return rv ? EXIT_FAILURE : EXIT_SUCCESS;
}
