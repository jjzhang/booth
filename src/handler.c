/* 
 * Copyright (C) 2014 Philipp Marek <philipp.marek@linbit.com>
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



/** Runs an external handler.
 * See eg. 'before-acquire-handler'.
 * TODO: timeout, async operation?. */
int run_handler(struct ticket_config *tk,
		const char *cmd, int synchronous)
{
	int rv;
	char expires[16];

	if (!cmd)
		return 0;

	assert(synchronous);
	sprintf(expires, "%" PRId64, (int64_t)wall_ts(&tk->term_expires));

	rv = setenv("BOOTH_TICKET", tk->name, 1) ||
		setenv("BOOTH_LOCAL", local->addr_string, 1) ||
		setenv("BOOTH_CONF_NAME", booth_conf->name, 1) ||
		setenv("BOOTH_CONF_PATH", cl.configfile, 1) ||
		setenv("BOOTH_TICKET_EXPIRES", expires, 1);

	if (rv) {
		log_error("Cannot set environment: %s", strerror(errno));
	} else {
		rv = system(cmd);
		if (rv)
			tk_log_warn("handler \"%s\" exited with error %s",
					cmd, interpret_rv(rv));
		else
			tk_log_debug("handler \"%s\" exited with success", cmd);
	}

	return rv;
}
