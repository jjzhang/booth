/* 
 * Copyright (C) 2014 Philipp Marek <philipp.marek@linbit.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "ticket.h"
#include "config.h"
#include "inline-fn.h"
#include "log.h"
#include "pacemaker.h"
#include "booth.h"
#include "handler.h"

static int set_booth_env(struct ticket_config *tk)
{
	int rv;
	char expires[16];

	sprintf(expires, "%" PRId64, (int64_t)wall_ts(&tk->term_expires));
	rv = setenv("BOOTH_TICKET", tk->name, 1) ||
		setenv("BOOTH_LOCAL", local->addr_string, 1) ||
		setenv("BOOTH_CONF_NAME", booth_conf->name, 1) ||
		setenv("BOOTH_CONF_PATH", cl.configfile, 1) ||
		setenv("BOOTH_TICKET_EXPIRES", expires, 1);

	if (rv) {
		log_error("Cannot set environment: %s", strerror(errno));
	}
	return rv;
}

static void
closefiles(void)
{
	int fd;

	/* close all descriptors except stdin/out/err */
	for (fd = getdtablesize() - 1; fd > STDERR_FILENO; fd--) {
		close(fd);
	}
}

/* run some external program
 * return codes:
 * RUNCMD_ERR: executing program failed (or some other failure)
 * RUNCMD_MORE: program forked, results later
 */
int run_handler(struct ticket_config *tk)
{
	int rv = 0;
	pid_t pid;

	if (!tk_test.prog)
		return 0;

	switch(pid=fork()) {
	case -1:
		log_error("fork: %s", strerror(errno));
		return RUNCMD_ERR;
	case 0: /* child */
		if (set_booth_env(tk)) {
			exit(1);
		}
		closefiles(); /* don't leak open files */
		execv(tk_test.prog, tk_test.argv);
		tk_log_error("%s: execv failed (%s)", tk_test.prog, strerror(errno));
		exit(1);
	default: /* parent */
		tk_test.pid = pid;
		tk_test.progstate = EXTPROG_RUNNING;
		rv = RUNCMD_MORE; /* program runs */
	}

	return rv;
}
