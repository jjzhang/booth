/*
 * Copyright (C) 2016 Jan Pokorny <jpokorny@redhat.com>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdint.h>
#include <stdlib.h>

#include <qb/qblog.h>

#include "logging_libqb.h"

int debug_level = 0;

/* ENV_X definitions based on glue/lib/clplumbing/cl_log.c of glue project:
   http://hg.linux-ha.org/glue */
#define ENV_HADEBUGVAL	"HA_debug"
#define ENV_LOGFENV	"HA_logfile"	/* well-formed log file :-) */
#define ENV_DEBUGFENV	"HA_debugfile"	/* Debug log file */
#define ENV_LOGFACILITY	"HA_logfacility"/* Facility to use for logger */
#define ENV_SYSLOGFMT	"HA_syslogmsgfmt"/* TRUE if we should use syslog message formatting */

void
alt_qb_inherit_logging_environment(void)
{
	char *inherit_env;

	/* Don't need to free the return pointer from getenv */
	inherit_env = getenv(ENV_HADEBUGVAL);
	if (inherit_env != NULL && atoi(inherit_env) != 0 )
		debug_level = atoi(inherit_env);

	inherit_env = getenv(ENV_LOGFENV);
	if (inherit_env != NULL && *inherit_env != '\0') {
		int32_t log_fd = qb_log_file_open(inherit_env);
		qb_log_ctl(log_fd, QB_LOG_CONF_ENABLED, QB_TRUE);
		/* do not log debug info even if debug_level non-zero */
		qb_log_filter_ctl(log_fd, QB_LOG_FILTER_ADD,
				  QB_LOG_FILTER_FILE, "*", LOG_INFO);
	}

	inherit_env = getenv(ENV_DEBUGFENV);
	if (inherit_env != NULL && *inherit_env != '\0') {
		int32_t log_fd = qb_log_file_open(inherit_env);
		qb_log_ctl(log_fd, QB_LOG_CONF_ENABLED, QB_TRUE);
	}

	inherit_env = getenv(ENV_LOGFACILITY);
	if (inherit_env != NULL && *inherit_env != '\0') {
		int fac = qb_log_facility2int(inherit_env);
		if (fac > 0)
			qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_FACILITY, fac);
		else
			qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_FALSE);
	}

	inherit_env = getenv(ENV_SYSLOGFMT);
	if (inherit_env != NULL && *inherit_env != '\0'
	&&	(	!strcasecmp(inherit_env, "false")
		||	!strcasecmp(inherit_env, "off")
		||	!strcasecmp(inherit_env, "no")
		||	!strcasecmp(inherit_env, "n")
		||	!strcasecmp(inherit_env, "0"))){
		enum qb_log_target_slot i;
		for (i = QB_LOG_TARGET_START; i < QB_LOG_TARGET_MAX; i++) {
			if (i == QB_LOG_SYSLOG || i == QB_LOG_BLACKBOX)
				continue;
			qb_log_format_set(i, NULL);
		}
	}
}
