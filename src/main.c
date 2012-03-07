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
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include "log.h"
#include "booth.h"
#include "config.h"
#include "transport.h"
#include "timer.h"
#include "pacemaker.h"
#include "ticket.h"
#include <error.h>

#define RELEASE_VERSION		"1.0"

#define CLIENT_NALLOC		32

int log_logfile_priority = LOG_INFO;
int log_syslog_priority = LOG_ERR;
int log_stderr_priority = LOG_ERR;

static int client_maxi;
static int client_size = 0;
struct client *client = NULL;
struct pollfd *pollfd = NULL;

int poll_timeout = -1;

typedef enum {
	ACT_ARBITRATOR = 1,
	ACT_SITE,
	ACT_CLIENT,
} booth_role_t;

typedef enum {
	OP_LIST = 1,
	OP_GRANT,
	OP_REVOKE,
} operation_t;

struct command_line {
	int type;		/* ACT_ */
	int op;			/* OP_ */
	int force;
	char site[BOOTH_NAME_LEN];
	char ticket[BOOTH_NAME_LEN]; 
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
	if (rv < 0) {
		log_error("write errno %d", errno);
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}

static int do_connect(const char *sock_path)
{
	struct sockaddr_un sun;
	socklen_t addrlen;
	int rv, fd;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		goto out;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(&sun.sun_path[1], sock_path);
	addrlen = sizeof(sa_family_t) + strlen(sun.sun_path+1) + 1;

	rv = connect(fd, (struct sockaddr *) &sun, addrlen);
	if (rv < 0) {
		close(fd);
		fd = rv;
	}
out:
	return fd;
}

static void init_header(struct boothc_header *h, int cmd, int option,
			int result, int data_len)
{
	memset(h, 0, sizeof(struct boothc_header));

	h->magic = BOOTHC_MAGIC;
	h->version = BOOTHC_VERSION;
	h->len = data_len;
	h->cmd = cmd;
	h->option = option;
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

static int setup_listener(const char *sock_path)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int rv, s;

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0) {
		log_error("socket error %d %d", s, errno);
		return s;
	}

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_LOCAL;
	strcpy(&addr.sun_path[1], sock_path);
	addrlen = sizeof(sa_family_t) + strlen(addr.sun_path+1) + 1;

	rv = bind(s, (struct sockaddr *) &addr, addrlen);
	if (rv < 0) {
		log_error("bind error %d %d", rv, errno);
		close(s);
		return rv;
	}

	rv = listen(s, 5);
	if (rv < 0) {
		log_error("listen error %d %d", rv, errno);
		close(s);
		return rv;
	}
	return s;
}

void process_connection(int ci)
{
	struct boothc_header h;
	char *data = NULL;
	char *site, *ticket;
	int local, rv;
	void (*deadfn) (int ci);

	rv = do_read(client[ci].fd, &h, sizeof(h));

	if (rv < 0) {
		log_error("connection %d read error %d", ci, rv);
		if (errno == ECONNRESET)
			log_debug("client %d aborted conection fd %d", ci, client[ci].fd);
		else 
			log_debug("client %d closed connnection fd %d", ci, client[ci].fd);

		deadfn = client[ci].deadfn;
		if(deadfn) {
			log_debug("run deadfn", ci, client[ci].fd);
			deadfn(ci);
		}
		return;
	}
	if (h.magic != BOOTHC_MAGIC) {
		log_error("connection %d magic error %x", ci, h.magic);
		return;
	}
	if (h.version != BOOTHC_VERSION) {
		log_error("connection %d version error %x", ci, h.version);
		return;
	}

	if (h.len) {
		data = malloc(h.len);
		if (!data) {
			log_error("process_connection no mem %u", h.len);
			return;
		}
		memset(data, 0, h.len);

		rv = do_read(client[ci].fd, data, h.len);
		if (rv < 0) {
			log_error("connection %d read data error %d", ci, rv);
			goto out;
		}
		h.len = 0;
	}

	switch (h.cmd) {
	case BOOTHC_CMD_LIST:
		assert(!data);
		h.result = list_ticket(&data, &h.len);
		break;

	case BOOTHC_CMD_GRANT:
		site = data;
		ticket = data + BOOTH_NAME_LEN;
		if (!check_ticket(ticket)) {
			h.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}
		if (!check_site(site, &local)) {
			h.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}
		if (local)
			h.result = grant_ticket(ticket, h.option);
		else
			h.result = BOOTHC_RLT_REMOTE_OP;
		break;

	case BOOTHC_CMD_REVOKE:
		site = data;
		ticket = data + BOOTH_NAME_LEN;
		if (!check_ticket(ticket)) {
			h.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}
		if (!check_site(site, &local)) {
			h.result = BOOTHC_RLT_INVALID_ARG;
			goto reply;
		}
		if (local)
			h.result = revoke_ticket(ticket, h.option);
		else
			h.result = BOOTHC_RLT_REMOTE_OP;
		break;

	default:
		log_error("connection %d cmd %x unknown", ci, h.cmd);
		break;
	}

reply:
	rv = do_write(client[ci].fd, &h, sizeof(h));
	if (rv < 0)
		log_error("connection %d write error %d", ci, rv);
	if (h.len) {
		rv = do_write(client[ci].fd, data, h.len);
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
		log_error("process_listener: accept error %d %d", fd, errno);
		return;
	}

	i = client_add(fd, process_connection, NULL);

	log_debug("add client connection %d fd %d", i, fd);
}

static int setup_config(int type)
{
	int rv;

	rv = read_config(BOOTH_DEFAULT_CONF);
	if (rv < 0)
		goto out;

	rv = check_config(type);
	if (rv < 0)
		goto out;

out:
	return rv;
}

static int setup_transport(void)
{
	int rv;

	rv = booth_transport[booth_conf->proto].init(ticket_recv);
	if (rv < 0)
		goto out;

	rv = booth_transport[TCP].init(NULL);
	if (rv < 0)
		goto out;

out:
	return rv;
}

static int setup_timer(void)
{
	return timerlist_init();
}

static int setup(int type)
{
	int rv;

	rv = setup_config(type);
	if (rv < 0)
		goto fail;

	rv = setup_timer();
	if (rv < 0)
		goto fail;

	rv = setup_transport();
	if (rv < 0)
		goto fail;

	rv = setup_ticket();
	if (rv < 0)
		goto fail;

	rv = setup_listener(BOOTHC_SOCK_PATH);
	if (rv < 0)
		goto fail;
	client_add(rv, process_listener, NULL);

	return 0;

fail:
	return -1;
}

static int loop(void)
{
	void (*workfn) (int ci);
	void (*deadfn) (int ci);
	int rv, i;

        while (1) {
                rv = poll(pollfd, client_maxi + 1, poll_timeout);
                if (rv == -1 && errno == EINTR)
                        continue;
                if (rv < 0) {
                        log_error("poll errno %d", errno);
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

static int do_list(void)
{
	struct boothc_header h, *rh;
	char *reply = NULL, *data;
	int data_len;
	int fd, rv;

	init_header(&h, BOOTHC_CMD_LIST, 0, 0, 0);

	fd = do_connect(BOOTHC_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out;
	}

	rv = do_write(fd, &h, sizeof(h));
	if (rv < 0)
		goto out_close;

	reply = malloc(sizeof(struct boothc_header));
	if (!reply) {
		rv = -ENOMEM;
		goto out_close;
	}

	rv = do_read(fd, reply, sizeof(struct boothc_header));
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
	rv = do_read(fd, data, data_len);
	if (rv < 0)
		goto out_free;

	do_write(STDOUT_FILENO, data, data_len);
	rv = 0;

out_free:
	free(reply);
out_close:
	close(fd);
out:
	return rv;
}

static int do_grant(void)
{
	char *buf;
	struct boothc_header *h, reply;
	int buflen;
	uint32_t force = 0;
	int fd, rv;

	buflen = sizeof(struct boothc_header) + 
		 sizeof(cl.site) + sizeof(cl.ticket);
	buf = malloc(buflen);
	if (!buf) {
		rv = -ENOMEM;
		goto out;
	}
	h = (struct boothc_header *)buf;
	if (cl.force)
		force = BOOTHC_OPT_FORCE;
	init_header(h, BOOTHC_CMD_GRANT, force, 0,
		    sizeof(cl.site) + sizeof(cl.ticket));
	strcpy(buf + sizeof(struct boothc_header), cl.site);
	strcpy(buf + sizeof(struct boothc_header) + sizeof(cl.site), cl.ticket);

        fd = do_connect(BOOTHC_SOCK_PATH);
        if (fd < 0) {
                rv = fd;
                goto out_free;
        }

        rv = do_write(fd, buf, buflen);
        if (rv < 0)
                goto out_close;

	rv = do_read(fd, &reply, sizeof(struct boothc_header));
	if (rv < 0)
		goto out_close;

	if (reply.result == BOOTHC_RLT_INVALID_ARG) {
		log_info("invalid argument!");
		rv = -1;
		goto out_close;
	}
	
	if (reply.result == BOOTHC_RLT_REMOTE_OP) {
		struct booth_node to;
		int s;

		memset(&to, 0, sizeof(struct booth_node));
		to.family = BOOTH_PROTO_FAMILY;
		strcpy(to.addr, cl.site);

		s = booth_transport[TCP].open(&to);
		if (s < 0)
			goto out_close;

		rv = booth_transport[TCP].send(s, buf, buflen);
		if (rv < 0) {
			booth_transport[TCP].close(s);
			goto out_close;
		}
		rv = booth_transport[TCP].recv(s, &reply,
					       sizeof(struct boothc_header));
		if (rv < 0) {	
			booth_transport[TCP].close(s);
			goto out_close;
		}
		booth_transport[TCP].close(s);
	}
 
	if (reply.result == BOOTHC_RLT_ASYNC) {
		log_info("grant command sent, but result is async.");
		rv = 0;
	} else if (reply.result == BOOTHC_RLT_SYNC_SUCC) {
		log_info("grant succeeded!");
		rv = 0;
	} else if (reply.result == BOOTHC_RLT_SYNC_FAIL) {
		log_info("grant failed!");
		rv = 0;
	} else {
		log_error("internal error!");
		rv = -1;
	}

out_close:
	close(fd);
out_free:
	free(buf);
out:
	return rv;
}

static int do_revoke(void)
{
	char *buf;
	struct boothc_header *h, reply;
	int buflen;
	uint32_t force = 0;
	int fd, rv;

	buflen = sizeof(struct boothc_header) +
		 sizeof(cl.site) + sizeof(cl.ticket);
	buf = malloc(buflen);
	if (!buf) {
		rv = -ENOMEM;
		goto out;
	}
	h = (struct boothc_header *)buf;
	if (cl.force)
		force = BOOTHC_OPT_FORCE;
	init_header(h, BOOTHC_CMD_REVOKE, force, 0,
		    sizeof(cl.site) + sizeof(cl.ticket));
	strcpy(buf + sizeof(struct boothc_header), cl.site);
	strcpy(buf + sizeof(struct boothc_header) + sizeof(cl.site), cl.ticket);


	fd = do_connect(BOOTHC_SOCK_PATH);
	if (fd < 0) {
		rv = fd;
		goto out_free;
	}
        
	rv = do_write(fd, buf, buflen);
        if (rv < 0)
                goto out_close;

	rv = do_read(fd, &reply, sizeof(struct boothc_header));
	if (rv < 0)
		goto out_close;

	if (reply.result == BOOTHC_RLT_INVALID_ARG) {
		log_info("invalid argument!");
		rv = -1;
		goto out_close;
	}

	if (reply.result == BOOTHC_RLT_REMOTE_OP) {
		struct booth_node to;
		int s;

		memset(&to, 0, sizeof(struct booth_node));
		to.family = BOOTH_PROTO_FAMILY;
		strcpy(to.addr, cl.site);

		s = booth_transport[TCP].open(&to);
		if (s < 0)
			goto out_close;

		rv = booth_transport[TCP].send(s, buf, buflen);
		if (rv < 0) {
			booth_transport[TCP].close(s);
			goto out_close;
		}
		rv = booth_transport[TCP].recv(s, &reply,
					       sizeof(struct boothc_header));
		if (rv < 0) {
			booth_transport[TCP].close(s);
			goto out_close;
		}
		booth_transport[TCP].close(s);
	}

	if (reply.result == BOOTHC_RLT_ASYNC) {
		log_info("revoke command sent, but result is async.");
		rv = 0;
	} else if (reply.result == BOOTHC_RLT_SYNC_SUCC) {
		log_info("revoke succeeded!");
		rv = 0;
	} else if (reply.result == BOOTHC_RLT_SYNC_FAIL) {
		log_info("revoke failed!");
		rv = 0;
	} else {
		log_error("internal error!");
		rv = -1;
	}

out_close:
	close(fd);
out_free:
	free(buf);
out:
	return rv;
}

static int lockfile(void)
{
	char path[PATH_MAX];
	char buf[16];
	struct flock lock;
	int fd, rv;

	snprintf(path, PATH_MAX, "%s/%s", BOOTH_RUN_DIR, BOOTH_LOCKFILE_NAME);

	fd = open(path, O_CREAT|O_WRONLY, 0666);
	if (fd < 0) {
                log_error("lockfile open error %s: %s",
                          path, strerror(errno));
                return -1;
        }       

        lock.l_type = F_WRLCK;
        lock.l_start = 0;
        lock.l_whence = SEEK_SET;
        lock.l_len = 0;
        
        rv = fcntl(fd, F_SETLK, &lock);
        if (rv < 0) {
                log_error("lockfile setlk error %s: %s",
                          path, strerror(errno));
                goto fail;
        }

        rv = ftruncate(fd, 0);
        if (rv < 0) {
                log_error("lockfile truncate error %s: %s",
                          path, strerror(errno));
                goto fail;
        }

        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "%d\n", getpid());

        rv = write(fd, buf, strlen(buf));
        if (rv <= 0) {
                log_error("lockfile write error %s: %s",
                          path, strerror(errno));
                goto fail;
        }

        return fd;
 fail:
        close(fd);
        return -1;
}

static void unlink_lockfile(int fd)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "%s/%s", BOOTH_RUN_DIR, BOOTH_LOCKFILE_NAME);
	unlink(path);
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
	printf("  -D            Enable debugging to stderr and don't fork\n");
	printf("  -t            ticket name\n");
	printf("  -s            site name\n");
	printf("  -f            ticket attribute: force, only valid when "
				"granting\n");
	printf("  -h            Print this help, then exit\n");
}

#define OPTION_STRING		"Dt:s:fh"

static char *logging_entity = NULL;

static int read_arguments(int argc, char **argv)
{
	int optchar;
	char *arg1 = argv[1];
	char *op = NULL;

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

	if (!strcmp(arg1, "arbitrator")) {
		cl.type = ACT_ARBITRATOR;
		logging_entity = DAEMON_NAME "-arbitrator";
		optind = 2;
	} else if (!strcmp(arg1, "site")) {
		cl.type = ACT_SITE;
		logging_entity = DAEMON_NAME "-site";
		optind = 2;
	} else if (!strcmp(arg1, "client")) {
		cl.type = ACT_CLIENT;
		if (argc < 3) {
			print_usage();
			exit(EXIT_FAILURE);
		}
		op = argv[2];
		optind = 3;
	} else {
		cl.type = ACT_CLIENT;
		op = argv[1];
		optind = 2;
	}

	switch (cl.type) {
	case ACT_ARBITRATOR:
		break;

	case ACT_SITE:
		break;

	case ACT_CLIENT:
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
		case 'D':
			debug_level = 1;
			log_logfile_priority = LOG_DEBUG;
			log_syslog_priority = LOG_DEBUG;
			break;

		case 't':
			if (cl.op == OP_GRANT || cl.op == OP_REVOKE)
				strcpy(cl.ticket, optarg);
			else {
				print_usage();
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			if (cl.op == OP_GRANT || cl.op == OP_REVOKE)
				strcpy(cl.site, optarg);
			else {
				print_usage();
				exit(EXIT_FAILURE);
			}
			break;

		case 'f':
			if (cl.op == OP_GRANT)
				cl.force = 1;
			else {
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
                        log_error("could not set SCHED_RR priority %d err %d",
                                   sched_param.sched_priority, errno);
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

static int do_server(int type)
{
	int fd;
	int rv = -1;

	if (!debug_level) {
		if (daemon(0, 0) < 0) {
			perror("daemon error");
			exit(EXIT_FAILURE);
		}
	}

	fd = lockfile();
	if (fd < 0)
		return fd;

	if (type == ARBITRATOR)
		log_info("BOOTH arbitrator daemon started");
	else if (type == SITE)
		log_info("BOOTH cluster site daemon started");

	set_scheduler();
	set_oom_adj(-16);

	rv = setup(SITE);
	if (rv == 0)
		rv = loop();

	unlink_lockfile(fd);

	return rv;
}

static int do_client(void)
{
	int rv = -1;

	switch (cl.op) {
	case OP_LIST:
		rv = do_list();
		break;

	case OP_GRANT:
		rv = do_grant();
		break;

	case OP_REVOKE:
		rv = do_revoke();
		break;
	}
	
	return rv;
}

int main(int argc, char *argv[])
{
	int rv;

	memset(&cl, 0, sizeof(cl));

	rv = read_arguments(argc, argv);
	if (rv < 0)
		goto out;

	if (cl.type == ACT_CLIENT) {
		cl_log_enable_stderr(TRUE);
		cl_log_set_facility(0);
	} else {
		cl_log_set_entity(logging_entity);
		cl_log_enable_stderr(debug_level ? TRUE : FALSE);
		cl_log_set_facility(HA_LOG_FACILITY);
	}
	cl_inherit_logging_environment(0);

	switch (cl.type) {
	case ACT_ARBITRATOR:
		rv = do_server(ARBITRATOR);
		break;

	case ACT_SITE:
		rv = do_server(SITE);
		break;

	case ACT_CLIENT:
		rv = do_client();
		break;
	}

out:
	return rv ? EXIT_FAILURE : EXIT_SUCCESS;
}
